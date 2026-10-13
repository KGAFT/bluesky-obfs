use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bsobfs::codec::fake_codec::{CredentialsSide, FakeCodec, FakeCodecCfg, ServerCredentialProvider};
use bsobfs::codec::fake_codec_limiter::FakeCodecRateLimiterCfg;
use bsobfs::http_proxy::proxy_endpoint::ProxyEndpoint;
use bsobfs::obfs_data::delay_generator::DelayType;
use bsobfs::obfs_data::pattern_store::PatternStore;
use bsobfs::obfs_data::replay_guard::ReplayGuard;
use bsobfs::the_fourth_utils::async_trait::async_trait;
use bsobfs::the_fourth_utils::sha2::{Digest, Sha256};
use bsobfs::util::io_util::{receive_message, send_message};
use bsobfs::wreq::IntoEmulation;
use bsobfs::wreq_util::Emulation;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

struct InMemoryUsers {
    passwords: HashMap<String, Vec<u8>>,
    last_auth_ms: Mutex<HashMap<String, u64>>,
}

#[async_trait]
impl ServerCredentialProvider for InMemoryUsers {
    async fn get_client_password(&self, login: &str, time_in_auth_ms: u64) -> Option<Vec<u8>> {
        let password = self.passwords.get(login)?;
        let mut last = self.last_auth_ms.lock().unwrap();
        if last.get(login).is_some_and(|&prev| time_in_auth_ms <= prev) {
            return None;
        }
        last.insert(login.to_string(), time_in_auth_ms);
        Some(password.clone())
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:443".into());
    let public_password = std::env::var("PUBLIC_PASSWORD").unwrap_or_else(|_| "HelloPassword".into());
    let cover_host = std::env::var("COVER_HOST").unwrap_or_else(|_| "www.example.com".into());

    let emulation = Emulation::Firefox151.into_emulation();
    let patterns = PatternStore::new("cli_pattern.bin", "serv_pattern.bin")
        .load_or_capture(emulation.clone(), format!("{cover_host}:443"), format!("https://{cover_host}/"))
        .await;

    let users = InMemoryUsers {
        passwords: HashMap::from([("client".to_string(), b"HelloPasswordForHandshake".to_vec())]),
        last_auth_ms: Mutex::new(HashMap::new()),
    };

    // Opt-in: with these limits a legitimate client was still refused as
    // rate-limited during the handshake in local testing.
    let rate_limiter = std::env::var("RATE_LIMIT").is_ok_and(|v| v == "1").then(|| {
        let mut limiter = FakeCodecRateLimiterCfg::default();
        limiter.client_pattern = patterns.client;
        limiter.bandwidth_max_derivation_percent = 0.8;
        limiter
    });

    let cfg = FakeCodecCfg {
        pattern: patterns.server,
        public_password: Sha256::digest(public_password.as_bytes()).to_vec(),
        credentials: CredentialsSide::Server(Arc::new(users)),
        target_sni: format!("https://{cover_host}/"),
        target_sni_connection_dest: format!("{cover_host}:443"),
        setup_proxy_port: 7756, // client-side only
        target_browser: emulation,
        message_padding_size: 12..50,
        server_id: b"example-server".to_vec(), // must match the client
        rate_limiter,
        max_adjusted_padding_derivation_percent: 0.8,
        allowed_delays: vec![
            DelayType::ArraySort((32, 2)),
            DelayType::SpinLoop(Duration::from_micros(150)),
        ],
        long_delay_secs: 2..8,
        handshake_timeout: Duration::from_secs(30),
        // One guard shared by every connection.
        replay_guard: Some(Arc::new(ReplayGuard::new(60_000))),
    };

    let listener = TcpListener::bind(&listen).await?;
    println!("listening on {listen}, cover site {cover_host}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        tokio::spawn(async move {
            match serve(stream, cfg).await {
                Some(dest) => println!("{peer}: tunnel to {dest} closed"),
                None => println!("{peer}: closed without a tunnel"),
            }
        });
    }
}

async fn serve(mut stream: TcpStream, cfg: FakeCodecCfg) -> Option<String> {
    stream.set_nodelay(true).ok()?;
    let mut codec = FakeCodec::new(cfg);
    if !codec.setup_stream(&mut stream).await {
        return None;
    }
    let mut tunnel = Framed::new(stream, codec);

    let first = receive_message(&mut tunnel).await.ok()??;
    let dest = String::from_utf8(first.to_vec()).ok()?;
    let (_endpoint, mut channel) = ProxyEndpoint::new(dest.clone()).await.ok()?;

    loop {
        tokio::select! {
            from_dest = channel.from_endpoint_rcv.recv() => {
                let Some(data) = from_dest else { break };
                if send_message(&mut tunnel, data).await.is_err() { break; }
            }
            from_client = receive_message(&mut tunnel) => match from_client {
                Ok(Some(data)) => {
                    if channel.to_endpoint_snd.send(data.freeze()).await.is_err() { break; }
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
    }
    Some(dest)
}
