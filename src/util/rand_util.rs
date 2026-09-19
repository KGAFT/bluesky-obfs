/// Fill a fresh vector with uniform random bytes over the **full** `0..=255`
/// range.
///
/// The previous implementation used `Uniform::new(0, u8::MAX)`, whose upper
/// bound is exclusive, so it never produced `0xFF` — a latent bias in every
/// padding buffer. It also rebuilt and `unwrap()`ed the distribution once per
/// byte, which is needlessly slow for the multi-kilobyte paddings this is
/// called with.
pub fn generate_random_u8_vec(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::fill(out.as_mut_slice());
    out
}