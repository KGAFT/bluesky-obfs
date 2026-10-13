//! Tunnel client with a local HTTPS proxy.
//!
//! Each tunnel carries one `CONNECT` session: the client handshakes with the
//! server, opens a local proxy, waits for one application to connect through
//! it, sends the requested `host:port` as the first tunnel message, then relays
//! until either side closes. After that it starts over with a fresh handshake.
//!
//! Only TLS traffic (HTTPS through `CONNECT`) can pass: the local proxy frames
//! TLS records.
//!
//! ```sh
//! SERVER=203.0.113.10:443 PUBLIC_PASSWORD=HelloPassword \
//! LOGIN=client PASSWORD=HelloPasswordForHandshake \
//!     cargo run --release --example client
//!
//! curl -x http://127.0.0.1:9985 https://example.com/
//! ```

use std::sync::Arc;
use std::time::Duration;

use bsobfs::codec::fake_codec::{ClientCredentialProvider, CredentialsSide, FakeCodec, FakeCodecCfg};
use bsobfs::http_proxy::proxy_interface::ProxyInterface;
use bsobfs::obfs_data::delay_generator::DelayType;
use bsobfs::obfs_data::pattern_store::PatternStore;
use bsobfs::the_fourth_utils::async_trait::async_trait;
use bsobfs::the_fourth_utils::sha2::{Digest, Sha256};
use bsobfs::util::io_util::{receive_message, send_message};
use bsobfs::wreq::IntoEmulation;
use bsobfs::wreq_util::Emulation;
use tokio::net::TcpStream;
use tokio_util::bytes::Bytes;
use tokio_util::codec::Framed;

struct StaticCredentials {
    login: Vec<u8>,
    password: Vec<u8>,
}

#[async_trait]
impl ClientCredentialProvider for StaticCredentials {
    async fn get_client_credentials(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        Some((self.login.clone(), self.password.clone()))
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() {
    let server = std::env::var("SERVER").expect("set SERVER=host:port");
    let local_port: u16 = env_or("LOCAL_PROXY_PORT", "9985").parse().expect("LOCAL_PROXY_PORT");
    let cover_host = env_or("COVER_HOST", "www.example.com");
    let public_password = env_or("PUBLIC_PASSWORD", "HelloPassword");

    let emulation = Emulation::Firefox151.into_emulation();
    let patterns = PatternStore::new("cli_pattern.bin", "serv_pattern.bin")
        .load_or_capture(emulation.clone(), format!("{cover_host}:443"), format!("https://{cover_host}/"))
        .await;

    let cfg = FakeCodecCfg {
        pattern: patterns.client,
        public_password: Sha256::digest(public_password.as_bytes()).to_vec(),
        credentials: CredentialsSide::Client(Arc::new(StaticCredentials {
            login: env_or("LOGIN", "client").into_bytes(),
            password: env_or("PASSWORD", "HelloPasswordForHandshake").into_bytes(),
        })),
        target_sni: format!("https://{cover_host}/"),
        target_sni_connection_dest: format!("{cover_host}:443"),
        // Bound on 127.0.0.1 during the handshake only; must differ from
        // LOCAL_PROXY_PORT.
        setup_proxy_port: 7756,
        target_browser: emulation,
        message_padding_size: 12..50,
        server_id: b"example-server".to_vec(), // must match the server
        rate_limiter: None,
        max_adjusted_padding_derivation_percent: 0.8,
        allowed_delays: vec![
            DelayType::ArraySort((32, 2)),
            DelayType::SpinLoop(Duration::from_micros(150)),
        ],
        long_delay_secs: 2..8,
        handshake_timeout: Duration::from_secs(30),
        replay_guard: None,
    };

    loop {
        match run_session(&server, local_port, cfg.clone()).await {
            Ok(dest) => println!("session to {dest} closed"),
            Err(e) => {
                eprintln!("session failed: {e}");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

async fn run_session(server: &str, local_port: u16, cfg: FakeCodecCfg) -> Result<String, String> {
    let mut stream = TcpStream::connect(server).await.map_err(|e| e.to_string())?;
    stream.set_nodelay(true).ok();

    let mut codec = FakeCodec::new(cfg);
    if !codec.setup_stream(&mut stream).await {
        return Err("handshake failed".into());
    }
    let mut tunnel = Framed::new(stream, codec);
    println!("tunnel ready, proxy on 127.0.0.1:{local_port}");

    let (mut proxy, mut channel) = ProxyInterface::new(local_port).await.map_err(|e| e.to_string())?;

    // The destination is known once the application's first bytes arrive.
    let first = channel.from_endpoint_rcv.recv().await.ok_or("proxy closed")?;
    let dest = proxy.connection_dest().await.ok_or("no destination")?;
    send_message(&mut tunnel, Bytes::from(dest.clone().into_bytes())).await.map_err(|e| e.to_string())?;
    send_message(&mut tunnel, first).await.map_err(|e| e.to_string())?;

    loop {
        tokio::select! {
            from_app = channel.from_endpoint_rcv.recv() => {
                let Some(data) = from_app else { break };
                if send_message(&mut tunnel, data).await.is_err() { break; }
            }
            from_server = receive_message(&mut tunnel) => match from_server {
                Ok(Some(data)) => {
                    if channel.to_endpoint_snd.send(data.freeze()).await.is_err() { break; }
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
    }
    Ok(dest)
}
