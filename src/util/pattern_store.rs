

use bsobfs::codec::tls_codec::TLS_HEADER_LEN;
use bsobfs::http_proxy::proxy_endpoint::ProxyEndpoint;
use bsobfs::http_proxy::proxy_interface::ProxyInterface;
use bsobfs::strategy::{ConnectionPattern, UsedPacketSize};
use bsobfs::tls_inspector::{TlsDirection, TlsRecordReassembler};
use bsobfs::tls_parser::TlsRecordType;
use bsobfs::util::io_util::{PacketAnalyzeFuture, hardwire_proxy_to_endpoint};
use bsobfs::wreq::{Client, Emulation, Proxy};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tfserver::structures::s_type;
use tokio::fs;
use tokio::sync::{Mutex, broadcast};

const CAPTURE_PROXY_PORT: u16 = 9999;

const DEFAULT_CLIENT_PATTERN_PATH: &str = "cli_pattern.bin";
const DEFAULT_SERVER_PATTERN_PATH: &str = "serv_pattern.bin";

#[derive(Clone)]
pub struct PatternPair {
    pub client: ConnectionPattern,
    pub server: ConnectionPattern,
}

pub struct PatternStore {
    client_path: PathBuf,
    server_path: PathBuf,
}

impl Default for PatternStore {
    fn default() -> Self {
        Self::new(DEFAULT_CLIENT_PATTERN_PATH, DEFAULT_SERVER_PATTERN_PATH)
    }
}

impl PatternStore {
    pub fn new(client_path: impl AsRef<Path>, server_path: impl AsRef<Path>) -> Self {
        Self {
            client_path: client_path.as_ref().to_path_buf(),
            server_path: server_path.as_ref().to_path_buf(),
        }
    }

    /// Reads both files. `None` if either is missing or does not decode -
    /// a half-present pair is useless, the two sides must match.
    pub async fn load(&self) -> Option<PatternPair> {
        let client_bytes = fs::read(&self.client_path).await.ok()?;
        let server_bytes = fs::read(&self.server_path).await.ok()?;

        let client = s_type::from_slice(client_bytes.as_slice()).ok()?;
        let server = s_type::from_slice(server_bytes.as_slice()).ok()?;
        Some(PatternPair { client, server })
    }

    pub async fn save(&self, patterns: &PatternPair) -> Option<()> {
        let client_bytes = s_type::to_bytes(&patterns.client)?;
        let server_bytes = s_type::to_bytes(&patterns.server)?;
        fs::write(&self.client_path, client_bytes).await.ok()?;
        fs::write(&self.server_path, server_bytes).await.ok()?;
        Some(())
    }


    pub async fn load_or_capture(
        &self,
        emulation: Emulation,
        target_dest: String,
        target_sni: String,
    ) -> PatternPair {
        if let Some(patterns) = self.load().await {
            return patterns;
        }
        let patterns = capture_tls_pattern(emulation, target_dest, target_sni).await;
        self.save(&patterns).await;
        patterns
    }
}

struct PatternCapture {
    reassembler: TlsRecordReassembler,
    patternizer: ConnectionPattern,
}


pub async fn capture_tls_pattern(
    emulation: Emulation,
    target_dest: String,
    target_sni: String,
) -> PatternPair {
    let proxy = ProxyInterface::new(CAPTURE_PROXY_PORT)
        .await
        .expect("Failed to create proxy");
    let endpoint = ProxyEndpoint::new(target_dest)
        .await
        .expect("Failed to create proxy endpoint");
    let stop_sig = broadcast::channel(1);

    let client_capture = Arc::new(Mutex::new(PatternCapture {
        reassembler: TlsRecordReassembler::new(TlsDirection::ClientToServer),
        patternizer: ConnectionPattern::new(),
    }));
    let server_capture = Arc::new(Mutex::new(PatternCapture {
        reassembler: TlsRecordReassembler::new(TlsDirection::ServerToClient),
        patternizer: ConnectionPattern::new(),
    }));

    let client_capture_clone = client_capture.clone();
    let server_capture_clone = server_capture.clone();
    tokio::spawn(async move {
        hardwire_proxy_to_endpoint(
            proxy.1,
            endpoint.1,
            stop_sig.1,
            Some(record_packet_sizes),
            Some(record_packet_sizes),
            Some(client_capture_clone),
            Some(server_capture_clone),
        )
        .await;
    });

    let client = Client::builder()
        .emulation(emulation)
        .proxy(Proxy::https(format!("http://127.0.0.1:{CAPTURE_PROXY_PORT}/")).unwrap())
        .build()
        .expect("client");

    let _ = client.get(target_sni).send().await.expect("response");

    stop_sig.0.send(()).unwrap();

    let mut client_lock = client_capture.lock().await;
    let mut server_lock = server_capture.lock().await;
    client_lock.patternizer.finalize();
    server_lock.patternizer.finalize();
    PatternPair {
        client: client_lock.patternizer.clone(),
        server: server_lock.patternizer.clone(),
    }
}


fn record_packet_sizes(
    app_data: Option<Arc<Mutex<PatternCapture>>>,
    packet: &[u8],
) -> PacketAnalyzeFuture<'_> {
    Box::pin(async move {
        let app_data = app_data.unwrap();
        let mut data_lock = app_data.lock().await;
        let records = data_lock.reassembler.inspect_bytes(packet);

        let record_sizes: Vec<usize> = records
            .iter()
            .filter(|record| record.header.record_type == TlsRecordType::ApplicationData)
            .map(|record| TLS_HEADER_LEN + record.header.len as usize)
            .collect();
        for size in record_sizes {
            data_lock
                .patternizer
                .insert_packet(UsedPacketSize { size, repeat_times: 1 });
        }
    })
}
