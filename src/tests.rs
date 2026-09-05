//#![cfg(test)]

use crate::http_proxy::proxy_endpoint::ProxyEndpoint;
use crate::http_proxy::proxy_interface::ProxyInterface;
use crate::tls_inspector::{TlsDirection, TlsRecordReassembler};
use crate::util::io_util::{PacketAnalyzeFuture, SenderSideChannel, hardwire_proxy_to_endpoint, receive_message, send_message};
use std::fs::File;
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use futures_util::StreamExt;
use rand::random_range;
use tfserver::async_trait::async_trait;
use tfserver::structures::s_type;
use tls_parser::TlsRecordType;
use tokio::fs;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, broadcast};
use tokio::time::sleep;
use tokio_util::bytes::Bytes;
use tokio_util::codec::Framed;
use wreq::{Client, IntoEmulation, Proxy};
use wreq_util::Emulation;
use crate::codec::fake_codec::{ClientCredentialProvider, CredentialsSide, FakeCodec, FakeCodecCfg, ServerCredentialProvider};
use crate::codec::fake_codec_limiter::FakeCodecRateLimiterCfg;
use crate::strategy::{ConnectionPattern, UsedPacketSize};
use crate::util::rand_util::generate_random_u8_vec;

#[tokio::test]
async fn test_proxy() {
    let proxy = ProxyInterface::new(9999).await;
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
    let proxy = ProxyInterface::new(9999).await;
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

struct TlsPatternTestStruct{
    reassembler: TlsRecordReassembler,
    patternizer: ConnectionPattern
}

#[tokio::test]
async fn test_tls_pattern() {
   let pattern = make_tls_pattern("www.google.com:443".to_string(), "https://www.google.com".to_string()).await;

    println!("Packets from client");

    pattern.0.known_packet_sizes().iter().for_each(|p|{
        println!("Size {} repeat times {}",p.0, p.1);
    });
    println!("Packets from server");

    pattern.1.known_packet_sizes().iter().for_each(|p|{
        println!("Size {} repeat times {}",p.0, p.1);
    })
}
//returns (client pattern, server pattern)
async fn make_tls_pattern(target_dest: String, target_sni: String) -> (ConnectionPattern, ConnectionPattern){
    let proxy = ProxyInterface::new(9999).await;
    let endpoint = ProxyEndpoint::new(target_dest)
        .await
        .expect("Failed to create proxy endpoint");
    let stop_sig = broadcast::channel(1);
    let reassembler1 = Arc::new(Mutex::new(TlsPatternTestStruct{reassembler: TlsRecordReassembler::new(TlsDirection::ClientToServer), patternizer: ConnectionPattern::new()}));
    let reassembler2 = Arc::new(Mutex::new(TlsPatternTestStruct{reassembler: TlsRecordReassembler::new(TlsDirection::ServerToClient), patternizer: ConnectionPattern::new()}));
    let reasm1_clone = reassembler1.clone();
    let reasm2_clone = reassembler2.clone();
    tokio::spawn(async move {
        hardwire_proxy_to_endpoint(
            proxy.1,
            endpoint.1,
            stop_sig.1,
            Some(test_record_pattern),
            Some(test_record_pattern),
            Some(reasm1_clone),
            Some(reasm2_clone),
        )
            .await;
    });

    let client = Client::builder()
        .emulation(Emulation::Firefox151)
        .proxy(Proxy::https("http://127.0.0.1:9999/").unwrap())
        .build()
        .expect("client");

    // let resp = client.get("https://tls.peet.ws/api/all").send().await.expect("response");
    let resp = client
        .get(target_sni)
        .send()
        .await
        .expect("response");

    let mut file = File::create("index.html").expect("create file");
    file.write_all(resp.text().await.expect("text").as_bytes())
        .expect("TODO: panic message");
    file.flush().expect("flush");
    stop_sig.0.send(()).unwrap();

    let mut reasm_lock1 = reassembler1.lock().await;
    let mut reasm_lock2 = reassembler2.lock().await;
    reasm_lock1.patternizer.finalize();
    reasm_lock2.patternizer.finalize();
    (reasm_lock1.patternizer.clone(), reasm_lock2.patternizer.clone())
}


pub struct TestServerCredProvider {}

#[async_trait]
impl ServerCredentialProvider for TestServerCredProvider {
    async fn get_client_password(&self, client_identity: &str) -> Option<Vec<u8>> {
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

async fn try_read_connection_pattern() -> Option<(ConnectionPattern, ConnectionPattern)> {

    let cli_pat_bytes = fs::read("cli_pattern.bin").await.ok()?;
    let serv_pat_bytes = fs::read("serv_pattern.bin").await.ok()?;

    if let Ok(client_pat) = s_type::from_slice(cli_pat_bytes.as_slice()) {
        if let Ok(server_pat) = s_type::from_slice(serv_pat_bytes.as_slice()) {
            return Some((client_pat, server_pat));
        }
    }
    None
}

async fn save_patterns(patterns: &(ConnectionPattern, ConnectionPattern)) -> Option<()>{
    let cli_bytes = s_type::to_bytes(&patterns.0)?;
    let serv_bytes = s_type::to_bytes(&patterns.1)?;
    fs::write("cli_pattern.bin", cli_bytes).await.ok()?;
    fs::write("serv_pattern.bin", serv_bytes).await.ok()?;
    Some(())
}


pub async fn test_fake_tls_codec_server(pbk_key: Vec<u8>){
    let mut connection_pattern = if let Some(pattern) = try_read_connection_pattern().await{
        pattern
    } else {
        let pat = make_tls_pattern("www.google.com:443".to_string(), "https://www.google.com".to_string()).await;
        save_patterns(&pat).await;
        pat
    };

    let mut rate_limiter_cfg = FakeCodecRateLimiterCfg::default();
    rate_limiter_cfg.client_pattern = connection_pattern.0;
    rate_limiter_cfg.bandwidth_max_derivation_percent = 0.8;
    let mut cfg_serv = FakeCodecCfg{
        pattern: connection_pattern.1,
        public_password: pbk_key,
        credentials: CredentialsSide::Server(Arc::new(TestServerCredProvider{})),
        target_sni: "https://www.google.com/".to_string(),
        target_sni_connection_dest: "www.google.com:443".to_string() ,
        remote_ip: "127.0.0.1:5543".to_socket_addrs()
            .unwrap()
            .next()
            .unwrap() ,
        setup_proxy_port: 7756,
        target_browser: Emulation::Firefox151.into_emulation(),
        message_padding_size: 12..50,
        server_id: b"test-server".to_vec(),
        rate_limiter: Some(rate_limiter_cfg),
        max_adjusted_padding_derivation_percent: 0.8f64,
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
                            send_message(&mut client, data).await;
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
    let mut connection_pattern = if let Some(pattern) = try_read_connection_pattern().await{
        pattern
    } else {
        let pat = make_tls_pattern("www.google.com:443".to_string(), "https://www.google.com".to_string()).await;
        save_patterns(&pat).await;
        pat
    };




    let mut cfg_client = FakeCodecCfg{
        pattern: connection_pattern.0,
        public_password: pbk_key,
        credentials: CredentialsSide::Client(Arc::new(TestClientCredProvider{})),
        target_sni: "https://www.google.com/".to_string(),
        target_sni_connection_dest: "www.google.com:443".to_string() ,
        remote_ip: "127.0.0.1:5543".to_socket_addrs()
            .unwrap()
            .next()
            .unwrap() ,
        setup_proxy_port: 7756,
        target_browser: Emulation::Firefox151.into_emulation(),
        message_padding_size: 12..50,
        server_id: b"test-server".to_vec(),
        rate_limiter: None,
        max_adjusted_padding_derivation_percent: 0.8f64,
    };

    let mut cli_codec = FakeCodec::new(cfg_client);
    let mut client = TcpStream::connect("127.0.01:443").await.unwrap();
    client.set_nodelay(true).unwrap();
    if cli_codec.setup_stream(&mut client).await{
        let mut client = Framed::new(client, cli_codec);
        let mut proxy_interface = ProxyInterface::new(9975).await;
        loop {
            tokio::select! {
                data = proxy_interface.1.from_endpoint_rcv.recv() => {
                    if let Some(data) = data{
                        send_message(&mut client, data).await;
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
) -> PacketAnalyzeFuture {
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
) -> PacketAnalyzeFuture {
    Box::pin(async move {
        let records = app_data.unwrap().lock().await.inspect_bytes(packet);
        records.iter().for_each(|record| {
            println!("record header from server: {:?}", record.header);
        });
    })
}


pub fn test_record_pattern(
    app_data: Option<Arc<Mutex<TlsPatternTestStruct>>>,
    packet: &[u8],
) -> PacketAnalyzeFuture {
    Box::pin(async move {
        let app_data = app_data.unwrap();
        let mut data_lock = app_data.lock().await;
        let records = data_lock.reassembler.inspect_bytes(packet);
        records.iter().for_each(|record| {
            if record.header.record_type == TlsRecordType::ApplicationData{
                data_lock.patternizer.insert_packet(UsedPacketSize{size: packet.len(), repeat_times: 0});
            }
        });
    })
}