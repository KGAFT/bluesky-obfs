use std::sync::atomic::{AtomicU64, Ordering};
use aead::AeadInPlace;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{ KeyInit},
};use hkdf::Hkdf;
use tfserver::sha2::Sha256;
use tokio_util::bytes::{Buf, BytesMut};
pub struct SessionKeys {
    pub send: Aes256Gcm,
    pub recv: Aes256Gcm,

    /// Local outbound packet counter
    send_counter: AtomicU64,

    /// Highest accepted inbound counter
    recv_counter: AtomicU64,
}


const COUNTER_LEN: usize = 8;
const TAG_LEN: usize = 16;


struct OffsetBuffer<'a> {
    buf: &'a mut BytesMut,
    offset: usize,
}

impl AsRef<[u8]> for OffsetBuffer<'_> {
    fn as_ref(&self) -> &[u8] { &self.buf[self.offset..] }
}

impl AsMut<[u8]> for OffsetBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] { &mut self.buf[self.offset..] }
}

impl aead::Buffer for OffsetBuffer<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.buf.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.buf.truncate(self.offset + len);
    }
}
impl SessionKeys {

    pub fn derive_session_keys(shared: &[u8], is_server: bool) -> Option<Self> {
        let hk = Hkdf::<Sha256>::new(None, shared);

        let mut key_a = [0u8; 32];
        let mut key_b = [0u8; 32];

        hk.expand(b"aes-tunnel-key-a", &mut key_a).ok()?;
        hk.expand(b"aes-tunnel-key-b", &mut key_b).ok()?;

        let (send_key, recv_key) = if is_server {
            (key_b, key_a)
        } else {
            (key_a, key_b)
        };

        Some(Self {
            send: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&send_key)),
            recv: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&recv_key)),
            send_counter: AtomicU64::new(1),
            recv_counter: AtomicU64::new(0),
        })
    }

    #[inline]
    fn nonce_from_counter(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    pub fn seal_in_place(&self, buf: &mut BytesMut) -> Option<()> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);

        if counter == u64::MAX {
            return None;
        }

        let counter_bytes = counter.to_be_bytes();
        let nonce_bytes = Self::nonce_from_counter(counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Reframe the plaintext as [counter | plaintext] in a buffer sized for
        // the tag too, so neither the prefix nor the tag append reallocates.
        // The plaintext moves exactly once (the `unsplit`); after `split`, `buf`
        // is empty with no spare capacity, so the `reserve` never copies.
        let plaintext = buf.split();
        buf.reserve(COUNTER_LEN + plaintext.len() + TAG_LEN);
        buf.extend_from_slice(&counter_bytes);
        buf.unsplit(plaintext);

        // Encrypt only the bytes after the counter prefix in place; the tag
        // lands in the reserved headroom. counter is included in AAD so any
        // wire tampering fails tag verification.
        let mut framed = OffsetBuffer { buf: &mut *buf, offset: COUNTER_LEN };
        self.send
            .encrypt_in_place(nonce, &counter_bytes, &mut framed)
            .ok()?;

        Some(())
    }

    pub fn open_in_place(&self, buf: &mut BytesMut) -> Option<()> {
        if buf.len() < COUNTER_LEN {
            return None;
        }

        let counter = u64::from_be_bytes(buf[..COUNTER_LEN].try_into().ok()?);

        if counter == u64::MAX {
            eprintln!("Counter maxed!");
            return None;
        }

        // compare-exchange loop — prevents TOCTOU race if called concurrently
        let mut last = self.recv_counter.load(Ordering::Acquire);
        loop {
            if counter <= last {
                eprintln!("Replay protection");
                return None; // replay or reorder
            }
            match self.recv_counter.compare_exchange_weak(
                last,
                counter,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => last = current, // another thread advanced it, retry
            }
        }

        let counter_bytes = counter.to_be_bytes();
        let nonce_bytes = Self::nonce_from_counter(counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Decrypt the ciphertext after the counter prefix in place; the tag is
        // truncated in place. AAD must match what seal used, otherwise tag fails.
        let mut framed = OffsetBuffer { buf: &mut *buf, offset: COUNTER_LEN };
        self.recv
            .decrypt_in_place(nonce, &counter_bytes, &mut framed)
            .ok()?;

        // Drop the counter prefix with a zero-copy advance so `buf` holds
        // exactly the recovered plaintext.
        buf.advance(COUNTER_LEN);

        Some(())
    }

    pub const fn seal_overhead() -> usize {
        COUNTER_LEN + TAG_LEN
    }


    pub const fn sealed_len(plaintext_len: usize) -> usize {
        plaintext_len + Self::seal_overhead()
    }

    pub const fn plaintext_len(sealed_len: usize) -> Option<usize> {
        sealed_len.checked_sub(Self::seal_overhead())
    }
}
