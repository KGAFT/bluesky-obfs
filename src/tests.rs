//#![cfg(test)]

use crate::http_proxy::proxy_endpoint::ProxyEndpoint;
use crate::http_proxy::proxy_interface::ProxyInterface;
use crate::util::io_util::{PacketAnalyzeFuture, SenderSideChannel, receive_message, send_message};
use crate::util::tls_inspector::TlsRecordReassembler;

use std::sync::Arc;
use std::time::Duration;

use crate::codec::fake_codec::{ClientCredentialProvider, CredentialsSide, FakeCodec, FakeCodecCfg, ServerCredentialProvider};
use crate::codec::fake_codec_limiter::FakeCodecRateLimiterCfg;
use crate::obfs_data::delay_generator::DelayType;
use crate::obfs_data::pattern_store::PatternStore;
use crate::obfs_data::replay_guard::ReplayGuard;
use the_fourth_utils::async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_util::bytes::Bytes;
use tokio_util::codec::Framed;
use wreq::IntoEmulation;
use wreq_util::Emulation;

#[cfg(test)]
use crate::util::io_util::hardwire_proxy_to_endpoint;
// Only the network tests below use these.
#[cfg(test)]
use crate::util::tls_inspector::TlsDirection;
#[cfg(test)]
use tokio::fs::File;
#[cfg(test)]
use tokio::io::AsyncWriteExt;
#[cfg(test)]
use tokio::sync::broadcast;
#[cfg(test)]
use wreq::{Client, Proxy};

#[tokio::test]
async fn test_proxy() {
    let proxy = ProxyInterface::new(9945).await.expect("bind local proxy");
    let endpoint = ProxyEndpoint::new("www.example.com:443".to_string())
        .await
        .expect("Failed to create proxy endpoint");
    let stop_sig = broadcast::channel(1);
    tokio::spawn(async move {
        hardwire_proxy_to_endpoint::<()>(proxy.1, endpoint.1, stop_sig.1, None, None, None, None)
            .await;
    });

    let client = Client::builder()
        .emulation(Emulation::Firefox151)
        .proxy(Proxy::https("http://127.0.0.1:9945/").unwrap())
        .build()
        .expect("client");

    let resp = client
        .get("https://www.example.com/")
        .send()
        .await
        .expect("response");

    let mut file = File::create("index.html").await.expect("create file");
    file.write_all(resp.text().await.expect("text").as_bytes()).await
        .expect("TODO: panic message");
    file.flush().await.expect("flush");
    stop_sig.0.send(()).unwrap();
}
#[tokio::test]
async fn test_tls_inspector() {
    let proxy = ProxyInterface::new(9999).await.expect("bind local proxy");
    let endpoint = ProxyEndpoint::new("www.example.com:443".to_string())
        .await
        .expect("Failed to create proxy endpoint");
    let stop_sig = broadcast::channel(1);
    let reassembler1 = Arc::new(Mutex::new(TlsRecordReassembler::new(TlsDirection::ClientToServer)));
    let reassembler2 = Arc::new(Mutex::new(TlsRecordReassembler::new(TlsDirection::ServerToClient)));
    tokio::spawn(async move {
        hardwire_proxy_to_endpoint(
            proxy.1,
            endpoint.1,
            stop_sig.1,
            Some(test_client_record_inspect),
            Some(test_server_record_inspect),
            Some(reassembler1),
            Some(reassembler2),
        )
        .await;
    });

    let client = Client::builder()
        .emulation(Emulation::Chrome149)
        .proxy(Proxy::https("http://127.0.0.1:9999/").unwrap())
        .build()
        .expect("client");

    // let resp = client.get("https://tls.peet.ws/api/all").send().await.expect("response");
    let resp = client
        .get("https://www.example.com/")
        .send()
        .await
        .expect("response");

    let mut file = File::create("index.html").await.expect("create file");
    file.write_all(resp.text().await.expect("text").as_bytes()).await
        .expect("TODO: panic message");
    file.flush().await.expect("flush");
    stop_sig.0.send(()).unwrap();
}


#[tokio::test]
async fn test_tls_pattern() {
    let pattern_store = PatternStore::new("cli_pattern.bin", "serv_pattern.bin");
    let emulation = Emulation::Firefox151.into_emulation();
    let pattern = pattern_store.load_or_capture(emulation, "www.example.com:443".to_string(), "https://www.example.com/".to_string()).await;

    println!("Packets from client");

    pattern.client.known_packet_sizes().iter().for_each(|p|{
        println!("Size {} repeat times {}",p.0, p.1);
    });
    println!("Packets from server");

    pattern.server.known_packet_sizes().iter().for_each(|p|{
        println!("Size {} repeat times {}",p.0, p.1);
    })
}



pub struct TestServerCredProvider {}

#[async_trait]
impl ServerCredentialProvider for TestServerCredProvider {
    async fn get_client_password(
        &self,
        _client_identity: &str,
        _time_in_auth_ms: u64,
    ) -> Option<Vec<u8>> {
        // NOTE: a real provider must reject a stale/replayed `_time_in_auth_ms`
        // (e.g. <= the last accepted value for this identity). The test provider
        // runs a single handshake, so it accepts unconditionally.
        Some("HelloPasswordForHandshake".as_bytes().to_vec())
    }
}

pub struct TestClientCredProvider{

}
#[async_trait]
impl ClientCredentialProvider for TestClientCredProvider{
    async fn get_client_credentials(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        Some(("client".as_bytes().to_vec(), ("HelloPasswordForHandshake".as_bytes().to_vec())))
    }
}



pub async fn test_fake_tls_codec_server(pbk_key: Vec<u8>){
    let pattern_store = PatternStore::new("cli_pattern.bin", "serv_pattern.bin");
    let emulation = Emulation::Firefox151.into_emulation();
    let pattern = pattern_store.load_or_capture(emulation.clone(), "www.example.com:443".to_string(), "https://www.example.com/".to_string()).await;


    let mut rate_limiter_cfg = FakeCodecRateLimiterCfg::default();
    rate_limiter_cfg.client_pattern = pattern.client;
    rate_limiter_cfg.bandwidth_max_derivation_percent = 0.8;
    let cfg_serv = FakeCodecCfg{
        pattern: pattern.server,
        public_password: pbk_key,
        credentials: CredentialsSide::Server(Arc::new(TestServerCredProvider{})),
        target_sni: "https://www.example.com/".to_string(),
        target_sni_connection_dest: "www.example.com:443".to_string() ,
        setup_proxy_port: 7756,
        target_browser: emulation,
        message_padding_size: 12..50,
        server_id: b"test-server".to_vec(),
        rate_limiter: Some(rate_limiter_cfg),
        max_adjusted_padding_derivation_percent: 0.8f64,
        allowed_delays: vec![DelayType::ArraySort((32, 2)), DelayType::SpinLoop(Duration::from_micros(150)), DelayType::ArraySort((22, 2))],
        long_delay_secs: 2..8,
        handshake_timeout: Duration::from_secs(30),
        replay_guard: Some(Arc::new(ReplayGuard::new(60_000))),
    };

    let listener = TcpListener::bind("0.0.0.0:443").await.unwrap();

        let mut cli = listener.accept().await.unwrap();
    cli.0.set_nodelay(true).unwrap();
        let mut codec = FakeCodec::new(cfg_serv);
        if codec.setup_stream(&mut cli.0).await{
            let mut client = Framed::new(cli.0, codec);
            let mut end_point: Option<(ProxyEndpoint, SenderSideChannel)> = None;
            loop {
                tokio::select! {
                    data = receive_msg_from_endpoint(&mut end_point) => {
                        if let Some(data) = data{
                            let _ = send_message(&mut client, data).await;
                        }
                    }
                    data = receive_message(&mut client) => {
                        if let Ok(data) = data{
                            if let Some(data) = data{
                                if end_point.is_none(){
                                    end_point = Some(ProxyEndpoint::new("distfiles.gentoo.org:443".to_string()).await.unwrap())
                                }
                                end_point.as_mut().unwrap().1.to_endpoint_snd.send(data.freeze()).await.unwrap();
                            }
                        }
                    }
                }
            }

        } else {
            eprintln!("Setup failed");
            return;
        }
}

async fn receive_msg_from_endpoint(end_point: &mut Option<(ProxyEndpoint, SenderSideChannel)>) -> Option<Bytes> {
    if let Some(end_point) = end_point {
        end_point.1.from_endpoint_rcv.recv().await
    } else {
        None
    }

}

pub async fn test_fake_tls_codec_client(pbk_key: Vec<u8>){
    let pattern_store = PatternStore::new("cli_pattern.bin", "serv_pattern.bin");
    let emulation = Emulation::Firefox151.into_emulation();
    let pattern = pattern_store.load_or_capture(emulation, "www.example.com:443".to_string(), "https://www.example.com/".to_string()).await;



    let cfg_client = FakeCodecCfg{
        pattern: pattern.client,
        public_password: pbk_key,
        credentials: CredentialsSide::Client(Arc::new(TestClientCredProvider{})),
        target_sni: "https://www.example.com/".to_string(),
        target_sni_connection_dest: "www.example.com:443".to_string() ,
        setup_proxy_port: 7756,
        target_browser: Emulation::Firefox151.into_emulation(),
        message_padding_size: 12..50,
        server_id: b"test-server".to_vec(),
        rate_limiter: None,
        max_adjusted_padding_derivation_percent: 0.8f64,
        allowed_delays: vec![DelayType::ArraySort((32, 2)), DelayType::SpinLoop(Duration::from_micros(150)), DelayType::ArraySort((22, 2))],
        long_delay_secs: 2..8,
        handshake_timeout: Duration::from_secs(30),
        replay_guard: None,
    };

    let mut cli_codec = FakeCodec::new(cfg_client);
    let mut client = TcpStream::connect("0.0.0.0:443").await.unwrap();
    client.set_nodelay(true).unwrap();
    if cli_codec.setup_stream(&mut client).await{
        let mut client = Framed::new(client, cli_codec);
        let mut proxy_interface = ProxyInterface::new(9985).await.expect("bind local proxy");
        loop {
            tokio::select! {
                data = proxy_interface.1.from_endpoint_rcv.recv() => {
                    if let Some(data) = data{
                        let _ = send_message(&mut client, data).await;
                    }
                }
                data = receive_message(&mut client) => {
                    if let Ok(data) = data{
                        if let Some(data) = data{
                            proxy_interface.1.to_endpoint_snd.send(data.freeze()).await.unwrap();
                        }
                    }
                }
            }
        }
    } else {
        eprintln!("Setup failed");
        panic!("Setup failed");
    }
}

pub fn test_client_record_inspect(
    app_data: Option<Arc<Mutex<TlsRecordReassembler>>>,
    packet: &[u8],
) -> PacketAnalyzeFuture<'_> {
    Box::pin(async move {
        let records = app_data.unwrap().lock().await.inspect_bytes(packet);
        records.iter().for_each(|record| {
            println!("record header from client: {:?}", record.header);
        });
    })
}

pub fn test_server_record_inspect(
    app_data: Option<Arc<Mutex<TlsRecordReassembler>>>,
    packet: &[u8],
) -> PacketAnalyzeFuture<'_> {
    Box::pin(async move {
        eprintln!("contents: {}",  String::from_utf8_lossy(packet));

        let records = app_data.unwrap().lock().await.inspect_bytes(packet);
        records.iter().for_each(|record| {
            println!("record header from server: {:?}", record.header);
        });
    })
}



/// Offline unit tests: no network, no fixed ports, no files outside the temp dir.
#[cfg(test)]
mod unit {
    use crate::codec::fake_codec_limiter::{FakeCodecRateLimiter, FakeCodecRateLimiterCfg};
    use crate::obfs_data::delay_generator::{DelayGenerator, DelayType};
    use crate::obfs_data::pattern_store::{PatternPair, PatternStore};
    use crate::obfs_data::replay_guard::{HELLO_NONCE_LEN, ReplayGuard};
    use crate::obfs_data::strategy::{ConnectionPattern, UsedPacketSize};
    use crate::util::crypt_util::{AES_GCM_OVERHEAD, aes256_gcm_decrypt, aes256_gcm_encrypt};
    use crate::util::rand_util::generate_random_u8_vec;
    use crate::util::tls_inspector::{TlsDirection, TlsInspectorState, TlsRecordReassembler};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};
    use the_fourth_utils::util::session_keys::{
        CONFIRM_LABEL_CLIENT, CONFIRM_LABEL_SERVER, SessionKeys, constant_time_eq,
        derive_confirmation_tag,
    };
    use tokio_util::bytes::BytesMut;

    fn packet(size: usize, repeat_times: usize) -> UsedPacketSize {
        UsedPacketSize { size, repeat_times }
    }

    /// 100 x3, 200 x1, 300 x2, finalized.
    fn sample_pattern() -> ConnectionPattern {
        let mut pattern = ConnectionPattern::new();
        pattern.insert_packet(packet(100, 1));
        pattern.insert_packet(packet(100, 2));
        pattern.insert_packet(packet(200, 1));
        pattern.insert_packet(packet(300, 2));
        pattern.finalize();
        pattern
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("bsobfs-{}-{}", std::process::id(), name))
    }

    // ---- ReplayGuard ----

    #[test]
    fn replay_guard_accepts_once() {
        let guard = ReplayGuard::new(60_000);
        let nonce = [7u8; HELLO_NONCE_LEN];
        let now = ReplayGuard::current_time_ms();
        assert!(guard.accept(&nonce, now));
        assert!(!guard.accept(&nonce, now), "replayed nonce must be rejected");
        assert!(guard.accept(&[8u8; HELLO_NONCE_LEN], now), "distinct nonce must pass");
    }

    #[test]
    fn replay_guard_rejects_bad_nonce_len() {
        let guard = ReplayGuard::new(60_000);
        let now = ReplayGuard::current_time_ms();
        assert!(!guard.accept(&[1u8; HELLO_NONCE_LEN - 1], now));
        assert!(!guard.accept(&[1u8; HELLO_NONCE_LEN + 1], now));
        assert!(!guard.accept(&[], now));
    }

    #[test]
    fn replay_guard_rejects_outside_window() {
        let guard = ReplayGuard::new(1_000);
        assert_eq!(guard.window_ms(), 1_000);
        let now = ReplayGuard::current_time_ms();
        assert!(!guard.accept(&[1u8; HELLO_NONCE_LEN], now - 10_000), "stale");
        assert!(!guard.accept(&[2u8; HELLO_NONCE_LEN], now + 10_000), "future-dated");
        assert!(guard.accept(&[3u8; HELLO_NONCE_LEN], now - 500), "inside skew");
    }

    // ---- DelayGenerator ----

    #[test]
    fn delay_generator_empty_is_noop() {
        let start = Instant::now();
        DelayGenerator::pick_and_perform_delay(&[]);
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn delay_generator_spin_loop_waits() {
        let dur = Duration::from_millis(5);
        let start = Instant::now();
        DelayGenerator::pick_and_perform_delay(&[DelayType::SpinLoop(dur)]);
        assert!(start.elapsed() >= dur);
    }

    #[test]
    fn delay_generator_array_sort_runs() {
        DelayGenerator::perform_delay(&DelayType::ArraySort((64, 4)));
        DelayGenerator::pick_and_perform_delay(&[
            DelayType::ArraySort((32, 2)),
            DelayType::SpinLoop(Duration::from_micros(150)),
            DelayType::ArraySort((22, 2)),
        ]);
    }

    #[tokio::test]
    async fn delay_generator_async_variant() {
        DelayGenerator::pick_and_perform_delay_async(&[]).await;

        let dur = Duration::from_millis(5);
        let start = Instant::now();
        DelayGenerator::pick_and_perform_delay_async(&[DelayType::SpinLoop(dur)]).await;
        assert!(start.elapsed() >= dur);

        DelayGenerator::pick_and_perform_delay_async(&[DelayType::ArraySort((32, 2))]).await;
    }

    // ---- ConnectionPattern ----

    #[test]
    fn connection_pattern_counts_repeats() {
        let pattern = sample_pattern();
        assert_eq!(pattern.order_overall_len(), 6);
        assert_eq!(pattern.bandwidth_overall_len(), 100 * 3 + 200 + 300 * 2);
        assert_eq!(pattern.known_packet_sizes().get(&100), Some(&3));
        assert_eq!(pattern.known_packet_sizes().get(&300), Some(&2));
        // Consecutive equal sizes collapse into one run.
        let runs: Vec<(usize, usize)> =
            pattern.order().iter().map(|p| (p.size, p.repeat_times)).collect();
        assert_eq!(runs, vec![(100, 3), (200, 1), (300, 2)]);
    }

    #[test]
    fn connection_pattern_index_mapping() {
        let pattern = sample_pattern();
        assert_eq!(pattern.overall_idx_to_order_idx(0), 0);
        assert_eq!(pattern.overall_idx_to_order_idx(2), 0);
        assert_eq!(pattern.overall_idx_to_order_idx(3), 1);
        assert_eq!(pattern.overall_idx_to_order_idx(5), 2);
        assert_eq!(pattern.overall_idx_to_order_idx(100), 2, "clamps past the end");
        assert_eq!(pattern.overall_idx_to_order_idx_backwards(0), 2);
        assert_eq!(pattern.overall_idx_to_order_idx_backwards(2), 1);
        assert_eq!(pattern.order_idx_to_overall_idx(0), 0);
        assert_eq!(pattern.order_idx_to_overall_idx(1), 3);
        assert_eq!(pattern.order_idx_to_overall_idx(2), 4);
    }

    #[test]
    fn connection_pattern_select_size() {
        let pattern = sample_pattern();
        assert!(pattern.check_if_size_exists(200));
        assert!(!pattern.check_if_size_exists(250));

        assert_eq!(pattern.select_packet_size(0, 0.5), None);
        assert_eq!(pattern.select_packet_size(90, 0.5), Some(100));
        assert_eq!(pattern.select_packet_size(150, 0.5), Some(200));
        assert_eq!(pattern.select_packet_size(150, 0.1), None, "200 is 33% over");
        assert_eq!(pattern.select_packet_size(301, 10.0), None, "nothing larger");

        for _ in 0..50 {
            let picked = pattern.select_packet_size_randomized(90, 3.0).unwrap();
            assert!([100, 200, 300].contains(&picked));
        }
        assert_eq!(pattern.select_packet_size_randomized(0, 1.0), None);

        assert_eq!(pattern.select_packet_size_with_random_padding_fallback(90, 0.5, 10..20), 100);
        for _ in 0..50 {
            let padded = pattern.select_packet_size_with_random_padding_fallback(1000, 0.5, 10..20);
            assert!((1010..1020).contains(&padded));
        }
    }

    #[test]
    fn connection_pattern_clear() {
        let mut pattern = sample_pattern();
        pattern.clear();
        assert_eq!(pattern.order_overall_len(), 0);
        assert_eq!(pattern.bandwidth_overall_len(), 0);
        assert!(pattern.order().is_empty());
        assert!(pattern.known_packet_sizes().is_empty());
        assert_eq!(pattern.select_packet_size(90, 10.0), None);
    }

    // ---- PatternStore ----

    #[tokio::test]
    async fn pattern_store_round_trip() {
        let client_path = temp_path("round-trip-cli.bin");
        let server_path = temp_path("round-trip-serv.bin");
        let store = PatternStore::new(&client_path, &server_path);

        let mut server = ConnectionPattern::new();
        server.insert_packet(packet(1400, 5));
        server.finalize();
        let pair = PatternPair { client: sample_pattern(), server };

        store.save(&pair).await.expect("save");
        let loaded = store.load().await.expect("load");

        assert_eq!(loaded.client.known_packet_sizes(), pair.client.known_packet_sizes());
        assert_eq!(loaded.client.order_overall_len(), pair.client.order_overall_len());
        assert_eq!(loaded.client.bandwidth_overall_len(), pair.client.bandwidth_overall_len());
        assert_eq!(loaded.server.known_packet_sizes(), pair.server.known_packet_sizes());
        // `sorted_packet_sizes` survives the round trip, so selection still works.
        assert_eq!(loaded.client.select_packet_size(150, 0.5), Some(200));
        assert_eq!(loaded.server.select_packet_size(1300, 0.5), Some(1400));

        let _ = std::fs::remove_file(client_path);
        let _ = std::fs::remove_file(server_path);
    }

    #[tokio::test]
    async fn pattern_store_load_missing_or_corrupt() {
        let client_path = temp_path("corrupt-cli.bin");
        let server_path = temp_path("corrupt-serv.bin");
        let store = PatternStore::new(&client_path, &server_path);
        assert!(store.load().await.is_none(), "missing files");

        std::fs::write(&client_path, b"not an rkyv archive").unwrap();
        std::fs::write(&server_path, b"not an rkyv archive").unwrap();
        assert!(store.load().await.is_none(), "corrupt files");

        let _ = std::fs::remove_file(client_path);
        let _ = std::fs::remove_file(server_path);
    }

    // ---- FakeCodecRateLimiter ----

    fn limiter() -> FakeCodecRateLimiter {
        FakeCodecRateLimiter::new(FakeCodecRateLimiterCfg {
            packet_count_slack: 0,
            bandwidth_slack_bytes: 0,
            out_of_pattern_packets_slack: 0,
            client_pattern: sample_pattern(),
            ..Default::default()
        })
    }

    #[test]
    fn rate_limiter_accepts_pattern_traffic() {
        let mut limiter = limiter();
        for size in [100, 100, 100, 200, 300, 300] {
            limiter.register_client_packet(&vec![0u8; size]);
        }
        assert!(limiter.check_if_valid());
    }

    #[test]
    fn rate_limiter_rejects_too_many_packets() {
        let mut limiter = limiter();
        // 6 in the pattern, +20% allowed => 7.2.
        for _ in 0..8 {
            limiter.register_client_packet(&vec![0u8; 100]);
        }
        assert!(!limiter.check_if_valid());
    }

    #[test]
    fn rate_limiter_rejects_out_of_pattern_sizes() {
        let mut limiter = limiter();
        // 6 * 50% = 3 out-of-pattern packets allowed.
        for _ in 0..4 {
            limiter.register_client_packet(&vec![0u8; 50]);
        }
        assert!(!limiter.check_if_valid());
    }

    #[test]
    fn rate_limiter_rejects_excess_bandwidth() {
        let mut limiter = limiter();
        // 1100 bytes in the pattern, +30% allowed => 1430.
        for _ in 0..5 {
            limiter.register_client_packet(&vec![0u8; 300]);
        }
        assert!(!limiter.check_if_valid());
    }

    // ---- TlsRecordReassembler ----

    #[test]
    fn tls_reassembler_flags_non_tls() {
        let mut reassembler = TlsRecordReassembler::new(TlsDirection::ClientToServer);
        assert_eq!(reassembler.state(), TlsInspectorState::Detecting);
        assert!(reassembler.inspect_bytes(b"GET / HTTP/1.1\r\n\r\n").is_empty());
        assert!(reassembler.is_not_tls());
        assert!(reassembler.inspect_bytes(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]).is_empty());
    }

    // ---- rand_util / crypt_util ----

    #[test]
    fn random_vec_has_requested_len_and_full_range() {
        assert!(generate_random_u8_vec(0).is_empty());
        assert_eq!(generate_random_u8_vec(37).len(), 37);
        // 64 KiB misses 0xFF with probability (255/256)^65536, i.e. never.
        assert!(generate_random_u8_vec(1 << 16).contains(&0xFF));
    }

    #[test]
    fn aes_gcm_round_trip() {
        let key = [0x42u8; 32];
        let message = b"hello through the tunnel";
        let sealed = aes256_gcm_encrypt(&key, message).unwrap();
        assert_eq!(sealed.len(), message.len() + AES_GCM_OVERHEAD);
        assert_eq!(aes256_gcm_decrypt(&key, &sealed).unwrap(), message);

        let other = aes256_gcm_encrypt(&key, message).unwrap();
        assert_ne!(sealed, other, "nonce must be random per message");

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(aes256_gcm_decrypt(&key, &tampered).is_err());
        assert!(aes256_gcm_decrypt(&[0x43u8; 32], &sealed).is_err());
        assert!(aes256_gcm_decrypt(&key, &sealed[..AES_GCM_OVERHEAD - 1]).is_err());
    }

    // ---- the_fourth_utils session keys ----

    fn session_pair(transcript: &[u8]) -> (SessionKeys, SessionKeys) {
        let shared = [9u8; 32];
        (
            SessionKeys::derive_session_keys(&shared, transcript, false).unwrap(),
            SessionKeys::derive_session_keys(&shared, transcript, true).unwrap(),
        )
    }

    #[test]
    fn session_keys_round_trip_both_directions() {
        let (client, server) = session_pair(b"transcript");
        for i in 0..5u8 {
            let plain = vec![i; 100 + i as usize];

            let mut buf = BytesMut::from(plain.as_slice());
            client.seal_in_place(&mut buf).unwrap();
            assert_eq!(buf.len(), SessionKeys::sealed_len(plain.len()));
            server.open_in_place(&mut buf).unwrap();
            assert_eq!(&buf[..], plain.as_slice());

            let mut buf = BytesMut::from(plain.as_slice());
            server.seal_in_place(&mut buf).unwrap();
            client.open_in_place(&mut buf).unwrap();
            assert_eq!(&buf[..], plain.as_slice());
        }
        assert_eq!(SessionKeys::plaintext_len(SessionKeys::sealed_len(10)), Some(10));
        assert_eq!(SessionKeys::plaintext_len(SessionKeys::seal_overhead() - 1), None);
    }

    #[test]
    fn session_keys_reject_tamper_reorder_and_mismatch() {
        let (client, server) = session_pair(b"transcript");

        let mut tampered = BytesMut::from(&b"payload"[..]);
        client.seal_in_place(&mut tampered).unwrap();
        tampered[0] ^= 1;
        assert!(server.open_in_place(&mut tampered).is_none());

        // Records must arrive in order: the counter is implicit.
        let (client, server) = session_pair(b"transcript");
        let mut first = BytesMut::from(&b"first"[..]);
        let mut second = BytesMut::from(&b"second"[..]);
        client.seal_in_place(&mut first).unwrap();
        client.seal_in_place(&mut second).unwrap();
        assert!(server.open_in_place(&mut second).is_none());

        // A different transcript yields different keys.
        let (client, _) = session_pair(b"transcript-a");
        let (_, server) = session_pair(b"transcript-b");
        let mut buf = BytesMut::from(&b"payload"[..]);
        client.seal_in_place(&mut buf).unwrap();
        assert!(server.open_in_place(&mut buf).is_none());

        let mut short = BytesMut::from(&[0u8; 3][..]);
        assert!(server.open_in_place(&mut short).is_none());
    }

    #[test]
    fn confirmation_tags() {
        let shared = [5u8; 32];
        let client_tag = derive_confirmation_tag(&shared, CONFIRM_LABEL_CLIENT, b"t").unwrap();
        let server_tag = derive_confirmation_tag(&shared, CONFIRM_LABEL_SERVER, b"t").unwrap();
        assert_ne!(client_tag, server_tag, "directions must not share a tag");
        assert_eq!(client_tag, derive_confirmation_tag(&shared, CONFIRM_LABEL_CLIENT, b"t").unwrap());
        assert_ne!(client_tag, derive_confirmation_tag(&shared, CONFIRM_LABEL_CLIENT, b"u").unwrap());
        assert_ne!(client_tag, derive_confirmation_tag(&[6u8; 32], CONFIRM_LABEL_CLIENT, b"t").unwrap());

        assert!(constant_time_eq(&client_tag, &client_tag));
        assert!(!constant_time_eq(&client_tag, &server_tag));
        assert!(!constant_time_eq(&client_tag, &client_tag[..31]));
    }
}
