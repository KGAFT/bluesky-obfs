use crate::codec::tls_codec::{TLS_HEADER_LEN, TLS_MAX_RECORD_LEN, TlsCodec};
use crate::http_proxy::proxy_endpoint::ProxyEndpoint;
use crate::http_proxy::proxy_interface::ProxyInterface;
use crate::strategy::ConnectionPattern;
use crate::util::crypt_util::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::util::io_util::{SenderSideChannel, receive_message, send_message};
use crate::util::ob_s_type::{ClientBeginStruct, ClientHelloStruct, ServerHelloStruct};
use crate::util::session_keys::SessionKeys;
use futures_util::{Sink, StreamExt};
use nom::Offset;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::fmt::format;
use std::net::SocketAddr;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use std::{io, mem};
use tfserver::async_trait::async_trait;
use tfserver::codec::codec_trait::TfCodec;
use tfserver::futures_util::SinkExt;
use tfserver::rand;
use tfserver::rand::Rng;
use tfserver::structures::s_type;
use tfserver::structures::temp_transport::TempTransport;
use tfserver::structures::transport::{AsyncReadWrite, Transport};
use tokio_util::bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, Framed, LengthDelimitedCodec};
use wreq::{Client, Emulation, Proxy};

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
    ///Return 0 - client identity, 1 - client password
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
            tls_codec: self.tls_codec.clone(),
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

        // base_tls_header only supplies content-type/version bytes [0..3];
        // bytes [3..5] (length) must reflect *this* record, not the captured one.
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
        let target_packet = self.select_packet_from_pattern(1, 1);
        eprintln!(
            "[FakeCodec DEBUG] handshake_from_client: Selected target packet index: {}",
            target_packet
        );
        let mut local_proxy = ProxyInterface::new(self.cfg.setup_proxy_port).await;
        let mut temp_transport = Framed::new(TempTransport::new(stream), TlsCodec::new());
        let client = self.init_wreq_instance();
        let mut packet_counter: usize = 0;
        let mut spake: Option<Spake2<Ed25519Group>> = None;
        let mut shared: Option<Vec<u8>> = None;
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
                    if let Err(err) = resp { eprintln!("[FakeCodec DEBUG] handshake_from_client: failed to connect to remote: {:?}", err); return None; }
                    eprintln!("[FakeCodec DEBUG] handshake_from_client: Successfully got target sni response");

                    let header = match base_tls_header.clone() {
                        Some(h) => h,
                        None => {
                            eprintln!("[FakeCodec DEBUG] handshake_from_client: WARNING: base_tls_header is None, using default zeroed header");
                            vec![0; TLS_HEADER_LEN]
                        }
                    };

                    if let Some(msg) = self.make_client_begin_msg(header).await {
                        eprintln!("[FakeCodec DEBUG] handshake_from_client: Sending client begin msg, len: {}", msg.len());
                        if send_message(&mut temp_transport, Bytes::from(msg)).await.is_err() {
                            eprintln!("[FakeCodec DEBUG] handshake_from_client: Failed to send client begin msg");
                            break;
                        }
                    } else {
                        eprintln!("[FakeCodec DEBUG] handshake_from_client: Failed to make client begin msg");
                    }
                    break;
                }
                packet_to_send = local_proxy.1.from_endpoint_rcv.recv() => {
                    if let Some(mut packet) = packet_to_send {
                        eprintln!("[FakeCodec DEBUG] handshake_from_client: Received packet from local_proxy, counter: {}, target: {}, packet_len: {}",
                        packet_counter, target_packet, packet.len());
                    packet_counter += 1;
                    if packet_counter == target_packet {
                        if base_tls_header.is_none() {
                            base_tls_header = Some(packet[..TLS_HEADER_LEN].to_vec());
                        }

                        let res = Self::inject_client_message(&self.cfg, packet.to_vec()).await;
                        if let Some(res) = res {
                            eprintln!("[FakeCodec DEBUG] handshake_from_client: Successfully injected client message at packet {}", packet_counter);
                            packet = Bytes::from(res.0);
                            spake = Some(res.1);
                        } else{
                            eprintln!("[FakeCodec DEBUG] handshake_from_client: Failed to inject client message at packet {}", packet_counter);
                            break;
                        }
                    }

                    eprintln!("[FakeCodec DEBUG] handshake_from_client: Sending packet {} to temp_transport (server), len: {}", packet_counter, packet.len());
                    if send_message(&mut temp_transport, packet).await.is_err() {
                        eprintln!("[FakeCodec DEBUG] handshake_from_client: Failed to send packet {} to temp_transport", packet_counter);
                        break;
                    }
                    eprintln!("[FakeCodec DEBUG] handshake_from_client: Successfully sent packet {} to temp_transport", packet_counter);

                }
                }
                recv_packet = receive_message(&mut temp_transport) => {
                    match recv_packet {
                    Ok(data) => {
                         if let Some(mut data) = data {
                            eprintln!("[FakeCodec DEBUG] handshake_from_client: Received packet from temp_transport, len: {}", data.len());
                            let mut packet_found = false;
                            if spake.is_some() {
                                if let Some(hello) = Self::probe_for_server_hello_struct(&self.cfg, &data.as_mut()[TLS_HEADER_LEN..]).await {
                                   eprintln!("[FakeCodec DEBUG] handshake_from_client: Probed server hello struct successfully");
                                   let spake_session = spake.take().unwrap();
                                   if let Ok(data) = spake_session.finish(hello.auth_data.as_slice()) {
                                       eprintln!("[FakeCodec DEBUG] handshake_from_client: SPAKE2 finish successful, shared secret derived");
                                       shared = Some(data);
                                   } else {
                                       eprintln!("[FakeCodec DEBUG] handshake_from_client: SPAKE2 finish failed");
                                       break;
                                   }
                                   let _ = local_proxy.1.to_endpoint_snd.send(Bytes::from(hello.original_packet)).await;
                                   packet_found = true;
                                } else {
                                    eprintln!("[FakeCodec DEBUG] handshake_from_client: Failed to probe server hello struct");
                                }
                            }
                            if !packet_found {
                                    eprintln!("[FakeCodec DEBUG] handshake_from_client: Forwarding packet to local_proxy (not packet_found)");
                                    let _ = local_proxy.1.to_endpoint_snd.send(data.freeze()).await;
                            }
                         }
                    }
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
        let mut proxy_endpoint: Option<(ProxyEndpoint, SenderSideChannel)> = None;
        eprintln!("[FakeCodec DEBUG] handshake_from_server: Connected to remote!");

        let mut temp_transport = Framed::new(TempTransport::new(stream), TlsCodec::new());
        let mut packet_counter: usize = 0;
        let mut shared: Option<Vec<u8>> = None;
        let mut client_hello: Option<ClientHelloStruct> = None;
        let mut target_packet: Option<usize> = None;
        let mut base_tls_header: Option<Vec<u8>> = None;
        eprintln!("[FakeCodec DEBUG] handshake_from_server: Starting receiving messages");

        loop {
            tokio::select! {
                recv_packet = receive_message(&mut temp_transport) => {
                    eprintln!("[FakeCodec DEBUG] handshake_from_server: Received something from remote ");
                    match recv_packet{
                        Ok(data) => {

                            if let Some(mut data) = data {
                                eprintln!("[FakeCodec DEBUG] handshake_from_server: Received packet {} from temp_transport (client), len: {}", packet_counter, data.len());

                                if shared.is_none() {
                                    let mut found = false;
                                    if client_hello.is_none() && let Some(mut hello) = Self::probe_for_client_hello_struct(&self.cfg, &data.as_mut()[TLS_HEADER_LEN..]).await{
                                        eprintln!("[FakeCodec DEBUG] handshake_from_server: Successfully probed ClientHelloStruct at packet {}", packet_counter);
                                        eprintln!("[FakeCodec DEBUG] handshake_from_server: original packet: {:?}", hello.original_packet);

                                        let orig_data = Bytes::from(hello.original_packet);
                                        hello.original_packet = vec![];

                                        let res =  self.try_send_to_remote(&mut proxy_endpoint, orig_data).await;
                                        if res.is_none(){
                                            eprintln!("[FakeCodec DEBUG] failed to send packet to remote!");
                                            break
                                        }
                                        found = true;
                                        client_hello = Some(hello);
                                        target_packet = Some(1);
                                        packet_counter = 0;
                                        eprintln!("[FakeCodec DEBUG] handshake_from_server: Selected target_packet {} for server injection", target_packet.unwrap());
                                    } else {
                                        eprintln!("[FakeCodec DEBUG] handshake_from_server: Packet {} is not a ClientHelloStruct, forwarding to proxy_endpoint", packet_counter);
                                    }

                                    if !found {
                                        eprintln!("[FakeCodec DEBUG] handshake_from_server: Forwarding packet {} to proxy_endpoint (Google)", packet_counter);
                                        let res = self.try_send_to_remote(&mut proxy_endpoint, data.freeze()).await;
                                        if res.is_none(){
                                            eprintln!("[FakeCodec DEBUG] failed to send packet to remote!");
                                            break
                                        }
                                    }
                                } else {
                                    if Self::probe_for_client_begin(&self.cfg,  &data.as_mut()[TLS_HEADER_LEN..]).await{
                                        eprintln!("[FakeCodec DEBUG] handshake_from_server: Received ClientBeginStruct, handshake complete");
                                        break;
                                    }
                                }
                            } else {
                                eprintln!("[FakeCodec DEBUG] handshake_from_server: Received None from temp_transport");
                            }
                        }
                        Err(terminates) => {
                            eprintln!("[FakeCodec DEBUG] handshake_from_server: receive_message error, terminates: {}", terminates);
                            if terminates {
                                break;
                            }
                        }
                    }
                }
                packet_to_send = self.get_from_remote(&mut proxy_endpoint) => {
                    if let Some(mut packet) = packet_to_send {
                        packet_counter += 1;
                        eprintln!("[FakeCodec DEBUG] handshake_from_server: Received packet from proxy_endpoint, counter: {}", packet_counter);
                        if let Some(target) = target_packet.as_ref() {
                            if base_tls_header.is_none() {
                                base_tls_header = Some(packet[..TLS_HEADER_LEN].to_vec());
                            }
                            if packet_counter == *target && let Some(hello) = client_hello.as_ref() {
                                eprintln!("[FakeCodec DEBUG] handshake_from_server: Injecting server message for target packet {}", target);
                                let res = Self::inject_server_message(&self.cfg, hello, packet.to_vec()).await;
                                if let Some(res) = res {
                                    eprintln!("[FakeCodec DEBUG] handshake_from_server: Successfully injected server message");
                                    packet = Bytes::from(res.0);
                                    if let Ok(data) = res.1.finish(hello.auth_data.as_slice()) {
                                        eprintln!("[FakeCodec DEBUG] handshake_from_server: SPAKE2 finish successful");
                                        shared = Some(data);
                                    } else {
                                        eprintln!("[FakeCodec DEBUG] handshake_from_server: SPAKE2 finish failed");
                                        break;
                                    }
                                } else {
                                    eprintln!("[FakeCodec DEBUG] handshake_from_server: Failed to inject server message");
                                    break;
                                }
                            }
                        }

                        if send_message(&mut temp_transport, packet).await.is_err() {
                            eprintln!("[FakeCodec DEBUG] handshake_from_server: Failed to send packet to temp_transport");
                            break;
                        }
                    } else {
                     //   eprintln!("[FakeCodec DEBUG] handshake_from_server: proxy_endpoint channel closed");
                    //    break
                    }
                }

            }
        }
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
            remote.replace(match ProxyEndpoint::new(self.cfg.target_sni_connection_dest.clone()).await {
                Ok(ep) => ep,
                Err(e) => {
                    eprintln!("[FakeCodec DEBUG] handshake_from_server: Failed to create ProxyEndpoint: {}", e);
                    return None;
                }
            });
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

    fn select_packet_from_pattern(&self, start_index: usize, end_offset: usize) -> usize {
        return 3;
        let mut attempts = 10;
        loop {
            let mut rng = rand::rng();
            let ordered_packets = self.cfg.pattern.order();

            if ordered_packets.is_empty() {
                eprintln!(
                    "[FakeCodec DEBUG] select_packet_from_pattern: pattern.order() is empty!"
                );
                return 0;
            }

            let max_idx = ordered_packets.len().saturating_sub(end_offset);
            let safe_start = start_index.min(max_idx.saturating_sub(1));
            let safe_end = max_idx.saturating_sub(1);

            if safe_start >= safe_end {
                eprintln!(
                    "[FakeCodec DEBUG] select_packet_from_pattern: Invalid range, returning 0"
                );
                return 0;
            }

            let idx = rng.random_range(safe_start..=safe_end);

            // Fixed potential panic: check bounds before accessing idx - 1 or idx + 1
            let is_unique = (idx == 0
                || ordered_packets[idx].size != ordered_packets[idx - 1].size)
                || (idx == ordered_packets.len() - 1
                    || ordered_packets[idx].size != ordered_packets[idx + 1].size);

            if is_unique {
                eprintln!(
                    "[FakeCodec DEBUG] select_packet_from_pattern: Selected unique index {}",
                    idx
                );
                return idx;
            } else if attempts <= 0 {
                eprintln!(
                    "[FakeCodec DEBUG] select_packet_from_pattern: Max attempts reached, returning index {}",
                    idx
                );
                return idx;
            } else {
                attempts -= 1;
            }
        }
    }

    async fn inject_client_message(
        cfg: &FakeCodecCfg,
        original_packet: Vec<u8>,
    ) -> Option<(Vec<u8>, Spake2<Ed25519Group>)> {
        eprintln!("[FakeCodec DEBUG] inject_client_message: Starting");
        let mut tls_header = (&original_packet[..TLS_HEADER_LEN]).to_vec();

        let mut client_message =
            ClientHelloStruct::new_with_random_padding(cfg.message_padding_size.clone());
        client_message.original_packet = original_packet;
        eprintln!("[FakeCodec DEBUG] inject_client_message: original packet: {:?}", client_message.original_packet);
        let cred_provider = match cfg.credentials.clone() {
            CredentialsSide::Server(_) => {
                eprintln!(
                    "[FakeCodec DEBUG] inject_client_message: Invalid credentials side (Server)"
                );
                return None;
            }
            CredentialsSide::Client(cred) => cred,
        };

        let creds = match cred_provider.get_client_credentials().await {
            Some(c) => c,
            None => {
                eprintln!(
                    "[FakeCodec DEBUG] inject_client_message: Failed to get client credentials"
                );
                return None;
            }
        };

        client_message.login = String::from_utf8_lossy(creds.0.as_slice()).to_string();
        eprintln!(
            "[FakeCodec DEBUG] inject_client_message: Client login: {}",
            client_message.login
        );

        let res = match Self::make_spake2_client_initial(cred_provider, cfg.server_id.as_slice())
            .await
        {
            Some(r) => r,
            None => {
                eprintln!(
                    "[FakeCodec DEBUG] inject_client_message: Failed to make spake2 client initial"
                );
                return None;
            }
        };
        client_message.auth_data = res.0;

        let data = match s_type::to_bytes(&client_message) {
            Some(d) => d.to_vec(),
            None => {
                eprintln!(
                    "[FakeCodec DEBUG] inject_client_message: Failed to serialize client message"
                );
                return None;
            }
        };

        let mut msg = match Self::encrypt_message_with_pub_key(
            data.as_slice(),
            cfg.public_password.as_slice(),
        )
        .await
        {
            Some(m) => m,
            None => {
                eprintln!("[FakeCodec DEBUG] inject_client_message: Failed to encrypt message");
                return None;
            }
        };

        let record_len = msg.len() as u16;
        if record_len > TLS_MAX_RECORD_LEN as u16 {
            eprintln!(
                "[FakeCodec DEBUG] inject_client_message: Record length {} exceeds max {}",
                record_len, TLS_MAX_RECORD_LEN
            );
            return None;
        }
        let record_len_bytes = record_len.to_be_bytes();
        tls_header[3] = record_len_bytes[0];
        tls_header[4] = record_len_bytes[1];
        tls_header.append(&mut msg);
        eprintln!(
            "[FakeCodec DEBUG] inject_client_message: Success, final packet len: {}",
            tls_header.len()
        );
        Some((tls_header, res.1))
    }

    async fn inject_server_message(
        cfg: &FakeCodecCfg,
        client_hello: &ClientHelloStruct,
        original_packet: Vec<u8>,
    ) -> Option<(Vec<u8>, Spake2<Ed25519Group>)> {
        eprintln!(
            "[FakeCodec DEBUG] inject_server_message: Starting for client: {}",
            client_hello.login
        );
        let mut tls_header = (&original_packet[..TLS_HEADER_LEN]).to_vec();

        let mut server_msg =
            ServerHelloStruct::new_with_random_padding(cfg.message_padding_size.clone());
        server_msg.original_packet = original_packet;

        let cred_provider = match cfg.credentials.clone() {
            CredentialsSide::Server(cred) => Some(cred),
            CredentialsSide::Client(_) => {
                eprintln!(
                    "[FakeCodec DEBUG] inject_server_message: Invalid credentials side (Client)"
                );
                None
            }
        }?;

        let server_auth = match Self::make_spake2_server_initial(
            cred_provider,
            cfg.server_id.as_slice(),
            client_hello.login.clone(),
        )
        .await
        {
            Some(sa) => sa,
            None => {
                eprintln!(
                    "[FakeCodec DEBUG] inject_server_message: Failed to make spake2 server initial"
                );
                return None;
            }
        };

        server_msg.auth_data = server_auth.0;

        let data = match s_type::to_bytes(&server_msg) {
            Some(d) => d.to_vec(),
            None => {
                eprintln!(
                    "[FakeCodec DEBUG] inject_server_message: Failed to serialize server message"
                );
                return None;
            }
        };

        let mut msg = match Self::encrypt_message_with_pub_key(
            data.as_slice(),
            cfg.public_password.as_slice(),
        )
        .await
        {
            Some(m) => m,
            None => {
                eprintln!("[FakeCodec DEBUG] inject_server_message: Failed to encrypt message");
                return None;
            }
        };

        let record_len = msg.len() as u16;
        if record_len > TLS_MAX_RECORD_LEN as u16 {
            eprintln!(
                "[FakeCodec DEBUG] inject_server_message: Record length {} exceeds max {}",
                record_len, TLS_MAX_RECORD_LEN
            );
            return None;
        }
        let record_len_bytes = record_len.to_be_bytes();
        tls_header[3] = record_len_bytes[0];
        tls_header[4] = record_len_bytes[1];
        tls_header.append(&mut msg);
        eprintln!(
            "[FakeCodec DEBUG] inject_server_message: Success, final packet len: {}",
            tls_header.len()
        );
        Some((tls_header, server_auth.1))
    }

    async fn make_client_begin_msg(&self, mut base_tls_header: Vec<u8>) -> Option<Vec<u8>> {
        let msg = ClientBeginStruct::new_with_random_padding(self.cfg.message_padding_size.clone());
        let data = s_type::to_bytes(&msg).unwrap().to_vec();
        let mut data = match Self::encrypt_message_with_pub_key(
            data.as_slice(),
            self.cfg.public_password.as_slice(),
        )
        .await
        {
            Some(d) => d,
            None => {
                eprintln!("[FakeCodec DEBUG] make_client_begin_msg: Encryption failed");
                return None;
            }
        };
        let record_len = data.len() as u16;
        if record_len > TLS_MAX_RECORD_LEN as u16 {
            eprintln!(
                "[FakeCodec DEBUG] make_client_begin_msg: Record length {} exceeds max {}",
                record_len, TLS_MAX_RECORD_LEN
            );
            return None;
        }
        let record_len_bytes = record_len.to_be_bytes();
        base_tls_header[3] = record_len_bytes[0];
        base_tls_header[4] = record_len_bytes[1];
        base_tls_header.append(&mut data);
        Some(base_tls_header)
    }

    async fn probe_for_client_begin(cfg: &FakeCodecCfg, packet: &[u8]) -> bool {
        eprintln!(
            "[FakeCodec DEBUG] probe_for_client_begin: Starting, packet len: {}",
            packet.len()
        );
        if let Some(msg) =
            Self::decrypt_message_with_pub_key(packet, cfg.public_password.as_slice()).await
        {
            if let Ok(open) = s_type::access::<ClientBeginStruct>(msg.as_slice()) {
                if ClientBeginStruct::validate_arc(open) {
                    eprintln!("[FakeCodec DEBUG] probe_for_client_begin: Success");
                    let _ = open;
                    return true;
                } else {
                    eprintln!("[FakeCodec DEBUG] probe_for_client_begin: Validation failed");
                }
            } else {
                eprintln!("[FakeCodec DEBUG] probe_for_client_begin: Access failed");
            }
        } else {
            eprintln!("[FakeCodec DEBUG] probe_for_client_begin: Decryption failed");
        }
        false
    }

    async fn probe_for_server_hello_struct(
        cfg: &FakeCodecCfg,
        packet: &[u8],
    ) -> Option<ServerHelloStruct> {
        eprintln!(
            "[FakeCodec DEBUG] probe_for_server_hello_struct: Starting, packet len: {}",
            packet.len()
        );
        if let Some(msg) =
            Self::decrypt_message_with_pub_key(&packet, cfg.public_password.as_slice()).await
        {
            if let Ok(open) = s_type::access::<ServerHelloStruct>(msg.as_slice()) {
                if ServerHelloStruct::validate_arc(open) {
                    eprintln!("[FakeCodec DEBUG] probe_for_server_hello_struct: Success");
                    let _ = open;
                    return Some(s_type::from_slice(msg.as_slice()).unwrap());
                } else {
                    eprintln!("[FakeCodec DEBUG] probe_for_server_hello_struct: Validation failed");
                }
            } else {
                eprintln!("[FakeCodec DEBUG] probe_for_server_hello_struct: Access failed");
            }
        } else {
            eprintln!("[FakeCodec DEBUG] probe_for_server_hello_struct: Decryption failed");
        }
        None
    }

    async fn probe_for_client_hello_struct(
        cfg: &FakeCodecCfg,
        data: &[u8],
    ) -> Option<ClientHelloStruct> {
        eprintln!(
            "[FakeCodec DEBUG] probe_for_client_hello_struct: Starting, data len: {}",
            data.len()
        );
        if let Some(msg) =
            Self::decrypt_message_with_pub_key(data, cfg.public_password.as_slice()).await
        {
            if let Ok(open) = s_type::access::<ClientHelloStruct>(msg.as_slice()) {
                if ClientHelloStruct::validate_arc(open) {
                    eprintln!("[FakeCodec DEBUG] probe_for_client_hello_struct: Success");
                    let _ = open;
                    return Some(s_type::from_slice(msg.as_slice()).unwrap());
                } else {
                    eprintln!("[FakeCodec DEBUG] probe_for_client_hello_struct: Validation failed");
                }
            } else {
                eprintln!("[FakeCodec DEBUG] probe_for_client_hello_struct: Access failed");
            }
        } else {
            eprintln!("[FakeCodec DEBUG] probe_for_client_hello_struct: Decryption failed");
        }
        None
    }

    async fn make_spake2_client_initial(
        cred: Arc<dyn ClientCredentialProvider>,
        server_id: &[u8],
    ) -> Option<(Vec<u8>, Spake2<Ed25519Group>)> {
        let creds = match cred.get_client_credentials().await {
            Some(c) => c,
            None => {
                eprintln!(
                    "[FakeCodec DEBUG] make_spake2_client_initial: get_client_credentials returned None"
                );
                return None;
            }
        };
        let (spake, outbound_msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(creds.1.as_slice()),
            &Identity::new(creds.0.as_slice()),
            &Identity::new(server_id),
        );
        eprintln!("[FakeCodec DEBUG] make_spake2_client_initial: SPAKE2 start_a successful");
        Some((outbound_msg, spake))
    }

    async fn make_spake2_server_initial(
        cred_provider: Arc<dyn ServerCredentialProvider>,
        server_id: &[u8],
        client_id: String,
    ) -> Option<(Vec<u8>, Spake2<Ed25519Group>)> {
        let password = match cred_provider.get_client_password(&client_id).await {
            Some(p) => p,
            None => {
                eprintln!(
                    "[FakeCodec DEBUG] make_spake2_server_initial: get_client_password returned None for client_id: {}",
                    client_id
                );
                return None;
            }
        };
        let client_identity = client_id.as_bytes();
        let (spake, outbound_msg) = Spake2::<Ed25519Group>::start_b(
            &Password::new(password),
            &Identity::new(client_identity),
            &Identity::new(server_id),
        );
        eprintln!("[FakeCodec DEBUG] make_spake2_server_initial: SPAKE2 start_b successful");
        Some((outbound_msg, spake))
    }

    async fn encrypt_message_with_pub_key(msg: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        let res = aes256_gcm_encrypt(key, msg);
        if res.is_err() {
            eprintln!(
                "[FakeCodec DEBUG] encrypt_message_with_pub_key: aes256_gcm_encrypt failed: {:?}",
                res.err().unwrap()
            );
            return None;
        }
        res.ok()
    }

    async fn decrypt_message_with_pub_key(msg: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        let res = aes256_gcm_decrypt(key, msg);
        if res.is_err() {
            eprintln!(
                "[FakeCodec DEBUG] decrypt_message_with_pub_key: aes256_gcm_decrypt failed: {:?}",
                res.err().unwrap()
            );
            return None;
        }
        res.ok()
    }
}
