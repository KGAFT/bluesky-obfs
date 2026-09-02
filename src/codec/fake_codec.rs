use crate::codec::spake2_injector::{Spake2Injector, Spake2State, is_application_data};
use crate::codec::tls_codec::{TLS_HEADER_LEN, TLS_MAX_RECORD_LEN, TlsCodec};
use crate::http_proxy::proxy_endpoint::ProxyEndpoint;
use crate::http_proxy::proxy_interface::ProxyInterface;
use crate::strategy::ConnectionPattern;
use crate::util::io_util::{SenderSideChannel, receive_message, send_message};
use crate::util::session_keys::SessionKeys;

use futures_util::{Sink, SinkExt, StreamExt};
use std::net::SocketAddr;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use std::io;
use tfserver::async_trait::async_trait;
use tfserver::codec::codec_trait::TfCodec;
use tfserver::structures::temp_transport::TempTransport;
use tfserver::structures::transport::{AsyncReadWrite, Transport};
use tokio::time::sleep;
use tokio_util::bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, Framed};
use wreq::{Client, Emulation, Proxy};
use crate::codec::fake_codec_limiter::FakeCodecRateLimiterCfg;

#[derive(Clone)]
pub struct FakeCodecCfg {
    pub pattern: ConnectionPattern,
    pub public_password: Vec<u8>,
    pub credentials: CredentialsSide,
    pub target_sni: String,
    pub target_sni_connection_dest: String,
    pub remote_ip: SocketAddr,
    pub setup_proxy_port: u16,
    pub target_browser: Emulation,
    pub message_padding_size: Range<usize>,
    pub server_id: Vec<u8>,
    pub rate_limiter: Option<FakeCodecRateLimiterCfg>
}

#[derive(Clone)]
pub enum CredentialsSide {
    Server(Arc<dyn ServerCredentialProvider>),
    Client(Arc<dyn ClientCredentialProvider>),
}

#[async_trait]
pub trait ServerCredentialProvider: Send + Sync + 'static {
    async fn get_client_password(&self, client_identity: &str) -> Option<Vec<u8>>;
}

#[async_trait]
pub trait ClientCredentialProvider: Send + Sync + 'static {
    async fn get_client_credentials(&self) -> Option<(Vec<u8>, Vec<u8>)>;
}

pub struct FakeCodec {
    cfg: FakeCodecCfg,
    session_keys: Option<SessionKeys>,
    base_tls_header: Option<Vec<u8>>,
    tls_codec: TlsCodec,
}

impl Clone for FakeCodec {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            session_keys: None,
            base_tls_header: None,
            tls_codec: TlsCodec::new(),
        }
    }
}

impl Decoder for FakeCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut frame = match self.tls_codec.decode(src)? {
            Some(f) => f,
            None => return Ok(None),
        };
        frame.advance(TLS_HEADER_LEN);
        if let Some(keys) = &self.session_keys {
            if keys.open_in_place(&mut frame).is_none() {
                eprintln!(
                    "[FakeCodec DEBUG] decode: decryption failed (open_in_place returned None)"
                );
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decryption failed",
                ));
            }
        } else {
            eprintln!("[FakeCodec DEBUG] decode: session_keys is None, cannot decrypt");
            return Err(io::Error::new(io::ErrorKind::Other, "decryption failed"));
        }
        Ok(Some(frame))
    }
}

impl Encoder<Bytes> for FakeCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let Some(keys) = &self.session_keys else {
            eprintln!("[FakeCodec DEBUG] encode: session_keys is None, cannot encrypt");
            return Err(io::Error::new(io::ErrorKind::Other, "encryption failed"));
        };

        let mut buf = BytesMut::from(item);
        if keys.seal_in_place(&mut buf).is_none() {
            eprintln!("[FakeCodec DEBUG] encode: encryption failed (seal_in_place returned None)");
            return Err(io::Error::new(io::ErrorKind::Other, "encryption failed"));
        }

        if buf.len() > TLS_MAX_RECORD_LEN {
            eprintln!(
                "[FakeCodec DEBUG] encode: sealed record {} exceeds max {}",
                buf.len(),
                TLS_MAX_RECORD_LEN
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "record too large",
            ));
        }

        let mut header = self.base_tls_header.as_ref().unwrap().clone();
        let len_bytes = (buf.len() as u16).to_be_bytes();
        header[3] = len_bytes[0];
        header[4] = len_bytes[1];

        dst.extend_from_slice(&header);
        dst.extend_from_slice(&buf);
        Ok(())
    }
}

#[async_trait]
impl TfCodec for FakeCodec {
    async fn initial_setup(&mut self, transport: &mut Transport) -> bool {
        self.setup_stream(transport).await
    }
}

impl FakeCodec {
    pub fn new(cfg: FakeCodecCfg) -> Self {
        Self {
            cfg,
            session_keys: None,
            base_tls_header: None,
            tls_codec: TlsCodec::new(),
        }
    }

    pub async fn setup_stream<T: AsyncReadWrite + Send + Sync>(&mut self, stream: &mut T) -> bool {
        eprintln!("[FakeCodec DEBUG] setup_stream: Starting setup");
        let (shared, is_server) = match self.cfg.credentials {
            CredentialsSide::Server(_) => {
                eprintln!("[FakeCodec DEBUG] setup_stream: Acting as Server");
                //@TODO remove
                sleep(Duration::from_secs(2)).await;

                (self.handshake_from_server(stream).await, true)
            }
            CredentialsSide::Client(_) => {
                eprintln!("[FakeCodec DEBUG] setup_stream: Acting as Client");
                    (self.handshake_from_client(stream).await, false)
            }
        };
        if let Some((shared, base_tls_header)) = shared {
            let session_keys = SessionKeys::derive_session_keys(shared.as_slice(), is_server);
            if let Some(keys) = session_keys {
                eprintln!("[FakeCodec DEBUG] setup_stream: Session keys derived successfully");
                self.session_keys = Some(keys);
                self.base_tls_header = Some(base_tls_header);
                return true;
            }
            eprintln!("[FakeCodec DEBUG] setup_stream: Failed to derive session keys");
            return false;
        } else {
            eprintln!("[FakeCodec DEBUG] setup_stream: Handshake returned None");
            return false;
        }
    }

    async fn handshake_from_client<T: AsyncReadWrite + Send + Sync>(
        &self,
        stream: &mut T,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        eprintln!("[FakeCodec DEBUG] handshake_from_client: Starting handshake");
        let mut injector = Spake2Injector::new(self.cfg.clone());
        let mut local_proxy = ProxyInterface::new(self.cfg.setup_proxy_port).await;
        let mut temp_transport = Framed::new(TempTransport::new(stream), TlsCodec::new());
        let client = self.init_wreq_instance();
        let mut base_tls_header: Option<Vec<u8>> = None;

        let req_fut = client
            .get(self.cfg.target_sni.clone())
            .timeout(Duration::from_secs(30))
            .read_timeout(Duration::from_secs(30))
            .send();
        tokio::pin!(req_fut);
        let mut req_done = false;

        loop {
            tokio::select! {
                resp = &mut req_fut, if !req_done => {
                    req_done = true;
                    if let Err(err) = resp {
                        eprintln!("[FakeCodec DEBUG] handshake_from_client: failed to connect to remote: {:?}", err);
                        return None;
                    }
                    eprintln!("[FakeCodec DEBUG] handshake_from_client: Successfully got target sni response");
                    match injector.state() {
                        Spake2State::SecondPartNegotiated(_) => {
                            let header = base_tls_header.clone().unwrap_or_else(|| {
                                eprintln!("[FakeCodec DEBUG] handshake_from_client: WARNING: base_tls_header is None, using default zeroed header");
                                vec![0; TLS_HEADER_LEN]
                            });
                            if let Some(msg) = injector.make_client_begin_msg(header).await {
                                eprintln!("[FakeCodec DEBUG] handshake_from_client: Sending client begin msg, len: {}", msg.len());
                                if send_message(&mut temp_transport, Bytes::from(msg)).await.is_err() {
                                    eprintln!("[FakeCodec DEBUG] handshake_from_client: Failed to send client begin msg");
                                }
                            } else {
                                eprintln!("[FakeCodec DEBUG] handshake_from_client: Failed to make client begin msg");
                            }
                        }
                        _ => {
                            eprintln!("Failed to handshake");
                            return None;
                        }
                    }
                    break;
                }
                packet_to_send = local_proxy.1.from_endpoint_rcv.recv() => {
                    let Some(packet) = packet_to_send else {
                        eprintln!("[FakeCodec DEBUG] handshake_from_client: local_proxy channel closed");
                        break;
                    };
                    if base_tls_header.is_none() && is_application_data(&packet) {
                        base_tls_header = Some(packet[..TLS_HEADER_LEN].to_vec());
                    }
                    match injector.on_local_packet(packet).await {
                        Some(out) => {
                            if send_message(&mut temp_transport, out).await.is_err() {
                                eprintln!("[FakeCodec DEBUG] handshake_from_client: Failed to send packet to temp_transport");
                                break;
                            }
                        }
                        None => {
                            eprintln!("[FakeCodec DEBUG] handshake_from_client: injection failed, aborting");
                            break;
                        }
                    }
                }
                recv_packet = receive_message(&mut temp_transport) => {
                    match recv_packet {
                        Ok(Some(data)) => {
                            match injector.on_remote_packet(data.freeze()).await {
                                Some(out) => {
                                    let _ = local_proxy.1.to_endpoint_snd.send(out).await;
                                }
                                None => {
                                    eprintln!("[FakeCodec DEBUG] handshake_from_client: finish failed, aborting");
                                    break;
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(terminates) => {
                            eprintln!("[FakeCodec DEBUG] handshake_from_client: receive_message error, terminates: {}", terminates);
                            if terminates {
                                break;
                            }
                        }
                    }
                }
            }
        }

        let shared = match injector.state() {
            Spake2State::SecondPartNegotiated(shared) => Some(shared.clone()),
            _ => None,
        };
        eprintln!(
            "[FakeCodec DEBUG] handshake_from_client: Exiting loop. shared is_some: {}, base_tls_header is_some: {}",
            shared.is_some(),
            base_tls_header.is_some()
        );
        Some((shared?, base_tls_header?))
    }

    async fn handshake_from_server<T: AsyncReadWrite + Send + Sync>(
        &self,
        stream: &mut T,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        eprintln!("[FakeCodec DEBUG] handshake_from_server: Starting handshake");
        let mut injector = Spake2Injector::new(self.cfg.clone());
        let mut proxy_endpoint: Option<(ProxyEndpoint, SenderSideChannel)> = None;
        let mut temp_transport = Framed::new(TempTransport::new(stream), TlsCodec::new());
        let mut base_tls_header: Option<Vec<u8>> = None;

        loop {
            tokio::select! {
                recv_packet = receive_message(&mut temp_transport) => {
                    match recv_packet {
                        Ok(Some(data)) => {
                            match injector.on_remote_packet(data.freeze()).await {
                                Some(out) => {
                                    if self.try_send_to_remote(&mut proxy_endpoint, out).await.is_none() {
                                        eprintln!("[FakeCodec DEBUG] handshake_from_server: failed to forward to remote");
                                        break;
                                    }
                                }
                                None => {
                                    eprintln!("[FakeCodec DEBUG] handshake_from_server: handshake complete");
                                    break;
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(terminates) => {
                            eprintln!("[FakeCodec DEBUG] handshake_from_server: receive_message error, terminates: {}", terminates);
                            if terminates {
                                break;
                            }
                        }
                    }
                }
                packet_to_send = self.get_from_remote(&mut proxy_endpoint) => {
                    let Some(packet) = packet_to_send else {
                        continue;
                    };
                    if base_tls_header.is_none() && is_application_data(&packet) {
                        base_tls_header = Some(packet[..TLS_HEADER_LEN].to_vec());
                    }
                    match injector.on_local_packet(packet).await {
                        Some(out) => {
                            if send_message(&mut temp_transport, out).await.is_err() {
                                eprintln!("[FakeCodec DEBUG] handshake_from_server: Failed to send packet to temp_transport");
                                break;
                            }
                        }
                        None => {
                            eprintln!("[FakeCodec DEBUG] handshake_from_server: injection failed, aborting");
                            break;
                        }
                    }
                }
            }
        }

        let shared = match injector.state() {
            Spake2State::SecondPartNegotiated(shared) => Some(shared.clone()),
            _ => None,
        };
        eprintln!(
            "[FakeCodec DEBUG] handshake_from_server: Exiting loop. shared is_some: {}, base_tls_header is_some: {}",
            shared.is_some(),
            base_tls_header.is_some()
        );
        Some((shared?, base_tls_header?))
    }

    fn init_wreq_instance(&self) -> Client {
        Client::builder()
            .read_timeout(Duration::from_secs(30))
            .tcp_user_timeout(Duration::from_secs(30))
            .tcp_happy_eyeballs_timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(30))
            .emulation(self.cfg.target_browser.clone())
            .proxy(
                Proxy::https(format!("http://127.0.0.1:{}/", self.cfg.setup_proxy_port)).unwrap(),
            )
            .connect_timeout(Duration::from_secs(30))
            .build()
            .expect("client")
    }

    async fn try_send_to_remote(
        &self,
        remote: &mut Option<(ProxyEndpoint, SenderSideChannel)>,
        data: Bytes,
    ) -> Option<()> {
        if remote.is_none() {
            remote.replace(
                match ProxyEndpoint::new(self.cfg.target_sni_connection_dest.clone()).await {
                    Ok(ep) => ep,
                    Err(e) => {
                        eprintln!(
                            "[FakeCodec DEBUG] handshake_from_server: Failed to create ProxyEndpoint: {}",
                            e
                        );
                        return None;
                    }
                },
            );
        }
        if let Some((_, sender)) = remote {
            sender.to_endpoint_snd.send(data).await.ok()?;
            Some(())
        } else {
            None
        }
    }

    async fn get_from_remote(
        &self,
        remote: &mut Option<(ProxyEndpoint, SenderSideChannel)>,
    ) -> Option<Bytes> {
        if let Some((_, sender)) = remote {
            sender.from_endpoint_rcv.recv().await
        } else {
            None
        }
    }
}