use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;


pub fn aes256_gcm_encrypt(
    key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("AES-256 key must be exactly 32 bytes");

    // GCM uses a 96-bit (12-byte) nonce.
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, message)?;

    // Store the nonce together with the ciphertext.
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

pub fn aes256_gcm_decrypt(
    key: &[u8],
    encrypted: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    if encrypted.len() < 12 + 16 {
        return Err(aes_gcm::Error);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("AES-256 key must be exactly 32 bytes");

    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];

    cipher.decrypt(nonce, ciphertext)
}