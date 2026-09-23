use crate::codec::spake2_injector::{Spake2Injector, Spake2State, is_application_data};
use crate::codec::tls_codec::{TLS_HEADER_LEN, TLS_MAX_RECORD_LEN, TlsCodec};
use crate::http_proxy::proxy_endpoint::ProxyEndpoint;
use crate::http_proxy::proxy_interface::ProxyInterface;
use crate::strategy::ConnectionPattern;
use crate::util::io_util::{SenderSideChannel, receive_message, send_message};
use crate::util::replay_guard::ReplayGuard;
use crate::util::session_keys::SessionKeys;

use crate::codec::fake_codec_limiter::FakeCodecRateLimiterCfg;
use std::io;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use tfserver::async_trait::async_trait;
use tfserver::codec::codec_trait::TfCodec;
use tfserver::structures::temp_transport::TempTransport;
use tfserver::structures::transport::{AsyncReadWrite, Transport};
use tokio_util::bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, Framed};
use wreq::{Client, Emulation, Proxy};
use crate::util::delay_generator::{DelayGenerator, DelayType};

#[derive(Clone)]
pub struct FakeCodecCfg {
    pub pattern: ConnectionPattern,
    pub public_password: Vec<u8>,
    pub credentials: CredentialsSide,
    pub target_sni: String,
    pub target_sni_connection_dest: String,
    pub setup_proxy_port: u16,
    pub target_browser: Emulation,
    pub message_padding_size: Range<usize>,
    pub server_id: Vec<u8>,
    pub rate_limiter: Option<FakeCodecRateLimiterCfg>,
    pub max_adjusted_padding_derivation_percent: f64,
    pub allowed_delays: Vec<DelayType>,
    pub long_delay_secs: Range<u16>,
    pub replay_guard: Option<Arc<ReplayGuard>>,
    pub handshake_timeout: Duration,
}

#[derive(Clone)]
pub enum CredentialsSide {
    Server(Arc<dyn ServerCredentialProvider>),
    Client(Arc<dyn ClientCredentialProvider>),
}

#[async_trait]
pub trait ServerCredentialProvider: Send + Sync + 'static {
    ///Store the time of last successfull auth in somewhere else database and so on, if the time is skewed,
    /// or equal or less the last db record it's obvious replay, return None
    async fn get_client_password(&self, client_identity: &str, time_in_auth_ms: u64) -> Option<Vec<u8>>;
}

#[async_trait]
pub trait ClientCredentialProvider: Send + Sync + 'static {
    async fn get_client_credentials(&self) -> Option<(Vec<u8>, Vec<u8>)>;
}

/// Bytes a tunnel record costs on the wire beyond its payload: the TLS record
/// header, the `u16` padding length, and the AEAD tag. The record counter is
/// implicit and contributes nothing here.
pub const RECORD_OVERHEAD: usize = TLS_HEADER_LEN + 2 + SessionKeys::seal_overhead();

pub struct FakeCodec {
    cfg: FakeCodecCfg,
    session_keys: Option<SessionKeys>,
    base_tls_header: Option<Vec<u8>>,
    tls_codec: TlsCodec,
    leftover: BytesMut,
}

impl Clone for FakeCodec {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            session_keys: None,
            base_tls_header: None,
            tls_codec: TlsCodec::new(),
            leftover: BytesMut::new(),
        }
    }
}

impl Decoder for FakeCodec {
    type Item = BytesMut;
    type Error = io::Error;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if !self.leftover.is_empty() {
            let mut combined = std::mem::take(&mut self.leftover);
            combined.unsplit(src.split());
            *src = combined;
        }

        let mut frame = match self.tls_codec.decode(src)? {
            Some(f) => f,
            None => return Ok(None),
        };
        frame.advance(TLS_HEADER_LEN);

        let Some(keys) = &self.session_keys else {
            return Err(io::Error::new(io::ErrorKind::Other, "decryption failed"));
        };
        if keys.open_in_place(&mut frame).is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "decryption failed"));
        }

        if frame.len() < 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short frame"));
        }
        let padding_len = frame.get_u16() as usize;
        if frame.len() < padding_len {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad padding len"));
        }
        frame.advance(padding_len);

        Ok(Some(frame))
    }
}

impl Encoder<Bytes> for FakeCodec {
    type Error = io::Error;
    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Snapshot so any error path can restore `dst` to exactly what it held
        // before this record — `dst` may already contain earlier encoded records.
        let original_len = dst.len();
        let Some(keys) = &self.session_keys else {
            dbg_log!("[FakeCodec DEBUG] encode: session_keys is None, cannot encrypt");
            return Err(io::Error::new(io::ErrorKind::Other, "encryption failed"));
        };

        // Size against the **wire** length, not the payload length.
        //
        // Picking the target from `item.len()` alone made every emitted record
        // exactly RECORD_OVERHEAD bytes larger than the size the pattern chose,
        // so the observed size distribution was the cover site's distribution
        // shifted by a fixed constant — a trivial distinguisher for anyone
        // comparing against genuine traffic to the same site.
        let min_wire_len = item.len() + RECORD_OVERHEAD;
        let target_wire_len = self
            .cfg
            .pattern
            .select_packet_size_with_random_padding_fallback(
                min_wire_len,
                self.cfg.max_adjusted_padding_derivation_percent,
                self.cfg.message_padding_size.clone(),
            );
        // Both branches of the fallback return a value >= the size passed in, so
        // this cannot underflow.
        let padding_len = target_wire_len - min_wire_len;
        debug_assert!(padding_len <= u16::MAX as usize);

        // plaintext body = [padding_len: u16][padding bytes][payload]
        let body_len = 2 + padding_len + item.len();
        let sealed_len = SessionKeys::sealed_len(body_len);
        debug_assert_eq!(TLS_HEADER_LEN + sealed_len, target_wire_len);

        if TLS_HEADER_LEN + sealed_len > TLS_MAX_RECORD_LEN {
            dbg_log!(
                "[FakeCodec DEBUG] encode: sealed record {} exceeds max {}",
                TLS_HEADER_LEN + sealed_len,
                TLS_MAX_RECORD_LEN
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "record too large",
            ));
        }

        let header = self.base_tls_header.as_ref().unwrap();
        // let len_bytes = (sealed_len as u16).to_be_bytes(); // REMOVE THIS
        // header[3] = len_bytes[0]; // REMOVE THIS
        // header[4] = len_bytes[1]; // REMOVE THIS

        dst.reserve(TLS_HEADER_LEN + sealed_len);
        dst.extend_from_slice(header);

        // Modify the length bytes directly in the destination buffer
        let len_pos = dst.len() - TLS_HEADER_LEN + 3;
        let len_bytes = (sealed_len as u16).to_be_bytes();
        dst[len_pos] = len_bytes[0];
        dst[len_pos + 1] = len_bytes[1];

        let body_start = dst.len();

        dst.put_u16(padding_len as u16);
        let pad_start = dst.len();
        dst.resize(pad_start + padding_len, 0);
        rand::fill(&mut dst[pad_start..pad_start + padding_len]);
        dst.extend_from_slice(&item);

        debug_assert_eq!(dst.len() - body_start, body_len);

        let mut body = dst.split_off(body_start);
        if keys.seal_in_place(&mut body).is_none() {
            dbg_log!("[FakeCodec DEBUG] encode: encryption failed (seal_in_place returned None)");
            dst.unsplit(body);
            // Restore `dst` to exactly what it held on entry. The previous
            // arithmetic subtracted `sealed_len + TLS_HEADER_LEN` from a buffer
            // that only grew by `body_len + TLS_HEADER_LEN` — the body is still
            // unsealed on this path — so it ate `seal_overhead()` bytes of
            // whatever records were already encoded ahead of this one.
            dst.truncate(original_len);
            return Err(io::Error::new(io::ErrorKind::Other, "encryption failed"));
        }
        debug_assert_eq!(body.len(), sealed_len);
        dst.unsplit(body);

        DelayGenerator::pick_and_perform_delay(self.cfg.allowed_delays.as_slice());

        Ok(())
    }
}

#[async_trait]
impl TfCodec for FakeCodec {
    ///If initial_setup failed multiple times, you've probably want to temporarily blacklist this client
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
            leftover: BytesMut::new(),
        }
    }
    ///If setup_stream failed multiple times, you've probably want to temporarily blacklist this client
    pub async fn setup_stream<T: AsyncReadWrite + Send + Sync>(&mut self, stream: &mut T) -> bool {
        dbg_log!("[FakeCodec DEBUG] setup_stream: Starting setup");
        let deadline = self.cfg.handshake_timeout;
        let (shared, is_server) = match self.cfg.credentials {
            CredentialsSide::Server(_) => {
                dbg_log!("[FakeCodec DEBUG] setup_stream: Acting as Server");
                DelayGenerator::pick_and_perform_delay_async(self.cfg.allowed_delays.as_slice()).await;
                let res = tokio::time::timeout(deadline, self.handshake_from_server(stream)).await;
                match res {
                    Ok(v) => (v, true),
                    Err(_) => {
                        dbg_log!("[FakeCodec DEBUG] setup_stream: server handshake timed out");
                        (None, true)
                    }
                }
            }
            CredentialsSide::Client(_) => {
                dbg_log!("[FakeCodec DEBUG] setup_stream: Acting as Client");
                let res = tokio::time::timeout(deadline, self.handshake_from_client(stream)).await;
                match res {
                    Ok(v) => (v, false),
                    Err(_) => {
                        dbg_log!("[FakeCodec DEBUG] setup_stream: client handshake timed out");
                        (None, false)
                    }
                }
            }
        };
        if let Some((shared, base_tls_header, transcript)) = shared {
            let session_keys =
                SessionKeys::derive_session_keys(shared.as_slice(), transcript.as_slice(), is_server);
            if let Some(keys) = session_keys {
                dbg_log!("[FakeCodec DEBUG] setup_stream: Session keys derived successfully");
                self.session_keys = Some(keys);
                self.base_tls_header = Some(base_tls_header);
                return true;
            }
            dbg_log!("[FakeCodec DEBUG] setup_stream: Failed to derive session keys");
            return false;
        } else {
            dbg_log!("[FakeCodec DEBUG] setup_stream: Handshake returned None");
            return false;
        }
    }

    async fn handshake_from_client<T: AsyncReadWrite + Send + Sync>(
        &mut self,
        stream: &mut T,
    ) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        dbg_log!("[FakeCodec DEBUG] handshake_from_client: Starting handshake");
        let mut injector = Spake2Injector::new(self.cfg.clone());

        let mut local_proxy = match ProxyInterface::new(self.cfg.setup_proxy_port).await {
            Ok(p) => p,
            Err(_e) => {
                dbg_log!(
                    "[FakeCodec DEBUG] handshake_from_client: failed to bind local setup proxy on port {}: {}",
                    self.cfg.setup_proxy_port, _e
                );
                return None;
            }
        };
        let mut temp_transport = Framed::new(TempTransport::new(stream), TlsCodec::new());
        let client = self.init_wreq_instance();
        let mut base_tls_header: Option<Vec<u8>> = None;

        let req_fut = client
            .get(self.cfg.target_sni.clone())
            .timeout(Duration::from_secs(30))
            .read_timeout(Duration::from_secs(30))
            .send();
        tokio::pin!(req_fut);

        loop {
            tokio::select! {
                resp = &mut req_fut => {
                    drop(local_proxy);
                    if let Err(_err) = resp {
                        dbg_log!("[FakeCodec DEBUG] handshake_from_client: failed to connect to remote: {:?}", _err);
                        return None;
                    }

                    dbg_log!("[FakeCodec DEBUG] handshake_from_client: Successfully got target sni response");
                    match injector.state() {
                        Spake2State::SecondPartNegotiated(_) => {}
                        _ => {
                            dbg_log!("Failed to handshake");
                            return None;
                        }
                    }
                    break;
                }
                packet_to_send = local_proxy.1.from_endpoint_rcv.recv() => {
                    let Some(packet) = packet_to_send else {
                        dbg_log!("[FakeCodec DEBUG] handshake_from_client: local_proxy channel closed");
                        break;
                    };
                    if base_tls_header.is_none() && is_application_data(&packet) {
                        base_tls_header = Some(packet[..TLS_HEADER_LEN].to_vec());
                    }
                    match injector.on_local_packet(packet).await {
                        Some(out) => {
                            DelayGenerator::pick_and_perform_delay_async(self.cfg.allowed_delays.as_slice()).await;
                            if send_message(&mut temp_transport, out).await.is_err() {
                                dbg_log!("[FakeCodec DEBUG] handshake_from_client: Failed to send packet to temp_transport");
                                break;
                            }
                        }
                        None => {
                            dbg_log!("[FakeCodec DEBUG] handshake_from_client: injection failed, aborting");
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
                                    dbg_log!("[FakeCodec DEBUG] handshake_from_client: finish failed, aborting");
                                    break;
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(terminates) => {
                            dbg_log!("[FakeCodec DEBUG] handshake_from_client: receive_message error, terminates: {}", terminates);
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
        }?;

        if let Some(packet) = injector.packet_after_handshake().await{
            DelayGenerator::pick_and_perform_delay_async(self.cfg.allowed_delays.as_slice()).await;
            send_message(&mut temp_transport, packet).await.ok()?;
        } else {
            return None;
        }

        let mut attempts = 0;
        loop{
            if let Ok(msg) = receive_message(&mut temp_transport).await {
                if let Some(msg) = msg {
                    if injector.probe_packet_after_handshake(msg.freeze()).await {
                        break;
                    }
                }
            }
            if attempts > 100 {
                return None;
            }
            attempts += 1;
        }

        if let Some(packet) = injector.packet_after_handshake().await{
            DelayGenerator::pick_and_perform_delay_async(self.cfg.allowed_delays.as_slice()).await;
            send_message(&mut temp_transport, packet).await.ok()?;
        } else {
            return None;
        }


        self.leftover = std::mem::take(temp_transport.read_buffer_mut());
        dbg_log!(
            "[FakeCodec DEBUG] handshake_from_client: Exiting loop, base_tls_header is_some: {}, leftover: {} bytes",
            base_tls_header.is_some(),
            self.leftover.len()
        );
        Some((shared, base_tls_header?, injector.transcript_bytes()))
    }

    async fn handshake_from_server<T: AsyncReadWrite + Send + Sync>(
        &mut self,
        stream: &mut T,
    ) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        dbg_log!("[FakeCodec DEBUG] handshake_from_server: Starting handshake");
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
                                        dbg_log!("[FakeCodec DEBUG] handshake_from_server: failed to forward to remote");
                                        break;
                                    }
                                }
                                None => {
                                    drop(proxy_endpoint);
                                    if injector.is_rate_limited() {
                                        dbg_log!("[FakeCodec DEBUG] handshake_from_server: rate limit exceeded, dropping");
                                    } else {
                                        dbg_log!("[FakeCodec DEBUG] handshake_from_server: handshake complete");
                                    }
                                    break;
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(terminates) => {
                            dbg_log!("[FakeCodec DEBUG] handshake_from_server: receive_message error, terminates: {}", terminates);
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
                            DelayGenerator::pick_and_perform_delay_async(self.cfg.allowed_delays.as_slice()).await;
                            if send_message(&mut temp_transport, out).await.is_err() {
                                dbg_log!("[FakeCodec DEBUG] handshake_from_server: Failed to send packet to temp_transport");
                                break;
                            }
                        }
                        None => {
                            dbg_log!("[FakeCodec DEBUG] handshake_from_server: injection failed, aborting");
                            break;
                        }
                    }
                }
            }
        }


        // A limiter drop must not be promoted into the tunnel just because the
        // SPAKE2 exchange happened to complete before the limit was hit.
        if injector.is_rate_limited() {
            dbg_log!("[FakeCodec DEBUG] handshake_from_server: refusing rate-limited connection");
            return None;
        }

        let shared = match injector.state() {
            Spake2State::SecondPartNegotiated(shared) => Some(shared.clone()),
            _ => None,
        }?;

        if let Some(packet) = injector.packet_after_handshake().await {
            DelayGenerator::pick_and_perform_delay_async(self.cfg.allowed_delays.as_slice()).await;
            send_message(&mut temp_transport, packet).await.ok()?;
        } else {
            return None;
        }
        let mut attempts = 0;
        loop{
            if let Ok(msg) = receive_message(&mut temp_transport).await {
                if let Some(msg) = msg {
                    if injector.probe_packet_after_handshake(msg.freeze()).await {
                        break;
                    }
                }
            }
            if attempts > 10 {
                return None;
            }
            attempts += 1;
        }

        // Hand the framer's residual read buffer to the codec. `Framed` reads in
        // chunks, so if the peer coalesced its final Begin record with the first
        // tunnel record into one segment, that tunnel record is sitting here and
        // is lost the moment `temp_transport` is dropped — the stream then
        // desyncs and the connection drops. This is the "garbage in the client
        // pipe" failure; commenting the line out hid it rather than fixing it.
        self.leftover = std::mem::take(temp_transport.read_buffer_mut());
        dbg_log!(
            "[FakeCodec DEBUG] handshake_from_server: Exiting loop. shared is_some: true, base_tls_header is_some: {}, leftover: {} bytes",
            base_tls_header.is_some(),
            self.leftover.len()
        );
        Some((shared, base_tls_header?, injector.transcript_bytes()))
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
                    Err(_e) => {
                        dbg_log!(
                            "[FakeCodec DEBUG] handshake_from_server: Failed to create ProxyEndpoint: {}",
                            _e
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
        match remote {
            Some((_, sender)) => sender.from_endpoint_rcv.recv().await,
            None => std::future::pending().await,
        }
    }
}
