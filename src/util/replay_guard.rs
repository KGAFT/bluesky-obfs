use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Sliding-window guard against a replayed `ClientHello`.
///
/// A timestamp alone cannot stop a replay: inside the accepted clock skew an
/// attacker can resend a recorded hello verbatim and the server will accept it,
/// run a fresh SPAKE2 exchange, and complete setup. That is precisely the probe
/// a DPI box wants — a real cover site would carry on serving, while a replayed
/// hello drives this server into tunnel mode where the next record fails to
/// decrypt and the connection drops. The timestamp bounds how long a recording
/// stays useful; this cache is what makes each one single-use within that
/// window.
///
/// Shared across every connection to one server, so it lives behind an `Arc` in
/// `FakeCodecCfg`.
pub struct ReplayGuard {
    /// Accepted clock skew in milliseconds, in both directions.
    window_ms: u64,
    /// nonce -> the hello's timestamp, used to expire the entry.
    seen: Mutex<HashMap<Vec<u8>, u64>>,
}

pub const HELLO_NONCE_LEN: usize = 16;

impl ReplayGuard {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ms,
            seen: Mutex::new(HashMap::new()),
        }
    }

    pub fn window_ms(&self) -> u64 {
        self.window_ms
    }

    fn now_ms() -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_millis() as u64)
    }

    /// Accept a hello exactly once inside the window.
    ///
    /// Returns `false` for a stale, future-dated, malformed or already-seen
    /// hello. Callers must treat `false` as "this was never a hello" and keep
    /// proxying to the cover site — anything else turns this into the oracle it
    /// exists to close.
    pub fn accept(&self, nonce: &[u8], time_ms: u64) -> bool {
        if nonce.len() != HELLO_NONCE_LEN {
            return false;
        }

        let Some(now) = Self::now_ms() else {
            return false;
        };

        // Reject in both directions: a future-dated hello would otherwise stay
        // replayable for as long as its timestamp leads our clock.
        let skew = now.abs_diff(time_ms);
        if skew > self.window_ms {
            return false;
        }

        let Ok(mut seen) = self.seen.lock() else {
            // A poisoned lock means some other thread panicked mid-update. Fail
            // closed on the auth decision, fail open on the connection.
            return false;
        };

        // Drop anything that can no longer be inside the window, so the map is
        // bounded by the hello rate over `window_ms` rather than by uptime.
        seen.retain(|_, ts| now.abs_diff(*ts) <= self.window_ms);

        if seen.contains_key(nonce) {
            return false;
        }

        seen.insert(nonce.to_vec(), time_ms);
        true
    }

    /// Current wall clock in milliseconds, for stamping an outbound hello.
    pub fn current_time_ms() -> u64 {
        Self::now_ms().unwrap_or(0)
    }
}