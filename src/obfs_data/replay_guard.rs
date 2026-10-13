use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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

   
    pub fn accept(&self, nonce: &[u8], time_ms: u64) -> bool {
        if nonce.len() != HELLO_NONCE_LEN {
            return false;
        }

        let Some(now) = Self::now_ms() else {
            return false;
        };

        let skew = now.abs_diff(time_ms);
        if skew > self.window_ms {
            return false;
        }

        let Ok(mut seen) = self.seen.lock() else {
            // A poisoned lock means some other thread panicked mid-update. Fail
            // closed on the auth decision, fail open on the connection.
            return false;
        };

       
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