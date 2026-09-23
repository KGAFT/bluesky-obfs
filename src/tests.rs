//#![cfg(test)]

use crate::http_proxy::proxy_endpoint::ProxyEndpoint;
use crate::http_proxy::proxy_interface::ProxyInterface;
use crate::tls_inspector::{ TlsRecordReassembler};
use crate::util::io_util::{PacketAnalyzeFuture, SenderSideChannel, receive_message, send_message};

use std::sync::Arc;
use std::time::Duration;

use tfserver::async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex};
use tokio_util::bytes::Bytes;
use tokio_util::codec::Framed;
use wreq::{IntoEmulation};
use wreq_util::Emulation;
use crate::codec::fake_codec::{ClientCredentialProvider, CredentialsSide, FakeCodec, FakeCodecCfg, ServerCredentialProvider};
use crate::codec::fake_codec_limiter::FakeCodecRateLimiterCfg;
use crate::util::delay_generator::DelayType;
use crate::util::replay_guard::ReplayGuard;
use crate::util::pattern_store::PatternStore;

#[tokio::test]
async fn test_proxy() {
    use crate::util::io_util::hardwire_proxy_to_endpoint;
    use tokio::sync::broadcast;

    let proxy = ProxyInterface::new(9999).await.expect("bind local proxy");
    let endpoint = ProxyEndpoint::new("www.google.com:443".to_string())
        .await
        .expect("Failed to create proxy endpoint");
    let stop_sig = broadcast::channel(1);
    tokio::spawn(async move {
        hardwire_proxy_to_endpoint::<()>(proxy.1, endpoint.1, stop_sig.1, None, None, None, None)
            .await;
    });

    let client = Client::builder()
        .emulation(Emulation::Firefox151)
        .proxy(Proxy::https("http://127.0.0.1:9999/").unwrap())
        .build()
        .expect("client");

    // let resp = client.get("https://tls.peet.ws/api/all").send().await.expect("response");
    let resp = client
        .get("https://www.google.com/")
        .send()
        .await
        .expect("response");

    let mut file = File::create("index.html").expect("create file");
    file.write_all(resp.text().await.expect("text").as_bytes())
        .expect("TODO: panic message");
    file.flush().expect("flush");
    stop_sig.0.send(()).unwrap();
}
#[tokio::test]
async fn test_tls_inspector() {
    let proxy = ProxyInterface::new(9999).await.expect("bind local proxy");
    let endpoint = ProxyEndpoint::new("www.google.com:443".to_string())
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
        .get("https://www.google.com/")
        .send()
        .await
        .expect("response");

    let mut file = File::create("index.html").expect("create file");
    file.write_all(resp.text().await.expect("text").as_bytes())
        .expect("TODO: panic message");
    file.flush().expect("flush");
    stop_sig.0.send(()).unwrap();
}


#[tokio::test]
async fn test_tls_pattern() {
    let pattern_store = PatternStore::new("cli_pattern.bin", "serv_pattern.bin");
    let emulation = Emulation::Firefox151.into_emulation();
    let pattern = pattern_store.load_or_capture(emulation, "www.pinterest.com:443".to_string(), "https://www.pinterest.com/".to_string()).await;

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
    let pattern = pattern_store.load_or_capture(emulation.clone(), "www.pinterest.com:443".to_string(), "https://www.pinterest.com/".to_string()).await;


    let mut rate_limiter_cfg = FakeCodecRateLimiterCfg::default();
    rate_limiter_cfg.client_pattern = pattern.client;
    rate_limiter_cfg.bandwidth_max_derivation_percent = 0.8;
    let cfg_serv = FakeCodecCfg{
        pattern: pattern.server,
        public_password: pbk_key,
        credentials: CredentialsSide::Server(Arc::new(TestServerCredProvider{})),
        target_sni: "https://www.pinterest.com/".to_string(),
        target_sni_connection_dest: "www.pinterest.com:443".to_string() ,
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

    let listener = TcpListener::bind("64.111.93.111:443").await.unwrap();

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
    let pattern = pattern_store.load_or_capture(emulation, "www.pinterest.com:443".to_string(), "https://www.pinterest.com/".to_string()).await;



    let cfg_client = FakeCodecCfg{
        pattern: pattern.client,
        public_password: pbk_key,
        credentials: CredentialsSide::Client(Arc::new(TestClientCredProvider{})),
        target_sni: "https://www.pinterest.com/".to_string(),
        target_sni_connection_dest: "www.pinterest.com:443".to_string() ,
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
    let mut client = TcpStream::connect("64.111.93.111:443").await.unwrap();
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

