use tfserver::sha2::{Digest, Sha256};
use crate::tests::{test_fake_tls_codec_client};

pub mod strategy;
pub mod http_proxy;
pub mod util;
pub mod tls_inspector;
pub mod tests;
pub mod authorization;
pub mod codec;

#[tokio::main]
pub async fn main() {
    let mut key = vec![0u8; 32];
    let pass = Sha256::digest("HelloPassword");
    key.copy_from_slice(pass.as_slice());

    let res = test_fake_tls_codec_client(key).await;
}