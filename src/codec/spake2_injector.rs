use crate::codec::fake_codec::{
    ClientCredentialProvider, CredentialsSide, FakeCodecCfg, ServerCredentialProvider,
};
use crate::codec::fake_codec_limiter::{FakeCodecRateLimiter};
use crate::codec::spake2_injector::Spake2State::FirstPartNegotiated;
use crate::codec::tls_codec::{TLS_HEADER_LEN, TLS_MAX_RECORD_LEN};
use crate::strategy::ConnectionPattern;
use crate::util::crypt_util::{AES_GCM_OVERHEAD, aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::util::ob_s_type::{ClientBeginStruct, ClientHelloStruct, PacketContainer, ServerBeginStruct, ServerHelloStruct};
use crate::util::replay_guard::{HELLO_NONCE_LEN, ReplayGuard};
use crate::util::session_keys::{
    CONFIRM_LABEL_CLIENT, CONFIRM_LABEL_SERVER, constant_time_eq, derive_confirmation_tag,
};
use crate::util::rand_util::generate_random_u8_vec;
use rand::{Rng, random_range};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::mem;
use std::sync::Arc;
use tfserver::structures::s_type;
use tokio_util::bytes::Bytes;

/// Upper bound on a login, enforced before it reaches a credential lookup.
pub const MAX_LOGIN_LEN: usize = 255;

/// Bytes added to a serialized `PacketContainer` before it reaches the wire:
/// the public-password AEAD's nonce and tag, then the TLS record header. Handed
/// to `wrap_existing_data` so its padding targets the finished record length
/// rather than the length of the struct inside it.
pub const HANDSHAKE_WIRE_OVERHEAD: usize = TLS_HEADER_LEN + AES_GCM_OVERHEAD;

pub enum FirstPartSpake2 {
    Client(Option<Spake2<Ed25519Group>>),
    Server(ClientHelloStruct),
}

pub enum Spake2State {
    Begin,
    FirstPartNegotiated(FirstPartSpake2),
    SecondPartNegotiated(Vec<u8>),
}

/// Everything both peers agreed on during the hello exchange, in a form both
/// sides serialize identically.
///
/// The confirmation tags and the tunnel keys are both bound to this, so a peer
/// that saw a different handshake — a replayed hello, a swapped login, a
/// tampered auth element — cannot produce a matching tag.
#[derive(Clone, Default)]
pub struct HandshakeTranscript {
    pub client_auth: Vec<u8>,
    pub server_auth: Vec<u8>,
    pub login: Vec<u8>,
    pub server_id: Vec<u8>,
    pub nonce: Vec<u8>,
    pub current_time: u64,
}

impl HandshakeTranscript {
    /// Length-prefix every field so no pair of distinct transcripts can
    /// serialize to the same bytes.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in [
            self.client_auth.as_slice(),
            self.server_auth.as_slice(),
            self.login.as_slice(),
            self.server_id.as_slice(),
            self.nonce.as_slice(),
        ] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&self.current_time.to_be_bytes());
        out
    }
}

pub struct Spake2Injector {
    state: Spake2State,
    tx_counter: usize,
    rx_counter: usize,
    cfg: FakeCodecCfg,
    target_packet: usize,
    rate_limiter: Option<FakeCodecRateLimiter>,
    base_tls_header: Option<Vec<u8>>,
    /// Set when the rate limiter rejected a record.
    ///
    /// `on_remote_packet` returns `None` for two unrelated reasons — "this
    /// record was consumed, the handshake milestone is reached" and "this client
    /// blew the rate limit, drop it". The handshake loop cannot tell them apart
    /// from the `Option` alone and treated both as success, so a rate-limited
    /// client that had already reached `SecondPartNegotiated` was promoted into
    /// the tunnel instead of being dropped.
    rate_limited: bool,
    /// Accumulates as the hello exchange progresses; complete once both auth
    /// elements have been seen. Feeds the confirmation tags and the tunnel keys.
    transcript: HandshakeTranscript,
}

impl Spake2Injector {
    pub fn new(mut cfg: FakeCodecCfg) -> Self {
        let target_packet = match cfg.credentials {
            CredentialsSide::Server(_) => random_range(1usize..3),
            CredentialsSide::Client(_) => Self::select_packet_from_pattern(&cfg.pattern, 1, 1),
        };
        dbg_log!("Spake2Injector: target_packet={}", target_packet);
        let rate_limiter = if let Some(limiter_cfg) = cfg.rate_limiter.take() {
            Some(FakeCodecRateLimiter::new(limiter_cfg))
        } else {
            None
        };
        Self {
            state: Spake2State::Begin,
            cfg,
            tx_counter: 0,
            rx_counter: 0,
            target_packet,
            rate_limiter,
            base_tls_header: None,
            rate_limited: false,
            transcript: HandshakeTranscript::default(),
        }
    }

    /// Whether the rate limiter rejected this connection. Distinguishes a
    /// limiter drop from an ordinary handshake-complete `None`.
    pub fn is_rate_limited(&self) -> bool {
        self.rate_limited
    }

    /// Serialized handshake transcript, for binding the tunnel keys to it.
    pub fn transcript_bytes(&self) -> Vec<u8> {
        self.transcript.bytes()
    }

    /// Shared secret, once the SPAKE2 exchange has completed.
    fn shared(&self) -> Option<&[u8]> {
        match &self.state {
            Spake2State::SecondPartNegotiated(shared) => Some(shared.as_slice()),
            _ => None,
        }
    }

    /// Our own confirmation tag — client tag when we are the client, server tag
    /// when we are the server.
    fn own_confirm_tag(&self) -> Option<[u8; 32]> {
        let label = match &self.cfg.credentials {
            CredentialsSide::Client(_) => CONFIRM_LABEL_CLIENT,
            CredentialsSide::Server(_) => CONFIRM_LABEL_SERVER,
        };
        derive_confirmation_tag(self.shared()?, label, &self.transcript.bytes())
    }

    /// The tag we expect from the peer.
    fn peer_confirm_tag(&self) -> Option<[u8; 32]> {
        let label = match &self.cfg.credentials {
            CredentialsSide::Client(_) => CONFIRM_LABEL_SERVER,
            CredentialsSide::Server(_) => CONFIRM_LABEL_CLIENT,
        };
        derive_confirmation_tag(self.shared()?, label, &self.transcript.bytes())
    }

    /// Constant-time check of a peer's confirmation tag.
    fn verify_peer_confirm(&self, presented: &[u8]) -> bool {
        let Some(expected) = self.peer_confirm_tag() else {
            return false;
        };
        constant_time_eq(&expected, presented)
    }

    pub async fn on_remote_packet(&mut self, data: Bytes) -> Option<Bytes> {
        match &self.cfg.credentials {
            CredentialsSide::Server(_) => self.on_server_side_remote_packet(data).await,
            CredentialsSide::Client(_) => self.on_client_side_remote_packet(data).await,
        }
    }

    pub async fn on_local_packet(&mut self, data: Bytes) -> Option<Bytes> {
        match &self.cfg.credentials {
            CredentialsSide::Server(_) => self.on_server_side_local_packet(data).await,
            CredentialsSide::Client(_) => self.on_client_side_local_packet(data).await,
        }
    }

    pub async fn packet_after_handshake(&mut self) -> Option<Bytes> {
        match &self.cfg.credentials {
            CredentialsSide::Server(_) => self.server_packet_after_handshake().await,
            CredentialsSide::Client(_) => self.client_packet_after_handshake().await,
        }
    }

    pub async fn probe_packet_after_handshake(&mut self, data: Bytes) -> bool {
        match &self.cfg.credentials {
            CredentialsSide::Server(_) => self.probe_on_server_side_packet_after_handshake(data).await,
            CredentialsSide::Client(_) => self.probe_on_client_side_packet_after_handshake(data).await,
        }
    }

    async fn probe_on_server_side_packet_after_handshake(&mut self, data: Bytes) -> bool {
        self.probe_for_client_begin(&data.as_ref()[TLS_HEADER_LEN..]).await
    }

    async fn probe_on_client_side_packet_after_handshake(&mut self, data: Bytes) ->bool {
        self.probe_for_server_begin(&data.as_ref()[TLS_HEADER_LEN..]).await
    }

    async fn server_packet_after_handshake(&mut self) -> Option<Bytes> {
        let confirm = self.own_confirm_tag()?;
        let header = self.base_tls_header.as_ref()?.to_vec();
        let packet = Self::make_server_begin_msg(&self.cfg, header, &confirm).await?;
        Some(Bytes::from_owner(packet))
    }

    async fn client_packet_after_handshake(&mut self)  -> Option<Bytes> {
        let confirm = self.own_confirm_tag()?;
        let header = self.base_tls_header.as_ref()?.to_vec();
        let packet = Self::make_client_begin_msg(&self.cfg, header, &confirm).await?;
        Some(Bytes::from_owner(packet))
    }


    async fn on_server_side_local_packet(&mut self, data: Bytes) -> Option<Bytes> {
        let is_app = is_application_data(&data);
        match &self.state {
            Spake2State::Begin => {
                if is_app {
                    self.tx_counter += 1;
                    if self.base_tls_header.is_none() {
                        self.base_tls_header = Some(data.as_ref()[..TLS_HEADER_LEN].to_vec());
                    }
                }
                Some(data)
            }
            Spake2State::FirstPartNegotiated(fp) => {

                if is_app && self.tx_counter >= self.target_packet {
                    self.tx_counter += 1;
                    match fp {
                        FirstPartSpake2::Client(_) => None,
                        FirstPartSpake2::Server(hello) => {
                            let res = Self::inject_server_message(&self.cfg, hello, data.to_vec())
                                .await;
                            if res.is_none(){
                                self.state = Spake2State::Begin;
                                return Some(data);
                            }
                            let res = res.unwrap();
                            let finished = res.1.finish(hello.auth_data.as_slice()).ok()?;

                            self.transcript.server_auth = res.2;
                            self.state = Spake2State::SecondPartNegotiated(finished);
                            Some(Bytes::from(res.0))
                        }
                    }
                } else {
                    if is_app {
                        self.tx_counter += 1;
                    }
                    Some(data)
                }
            }
            Spake2State::SecondPartNegotiated(_) => {
                if is_app {
                    self.tx_counter += 1;
                }
                Some(data)
            }
        }
    }

    async fn on_server_side_remote_packet(&mut self, data: Bytes) -> Option<Bytes> {
        let is_app = is_application_data(&data);

        if is_app && let Some(limiter) = self.rate_limiter.as_mut() {
            limiter.register_client_packet(data.as_ref());
            if !limiter.check_if_valid() {
                self.rate_limited = true;
                return None;
            }
        }

        match &self.state {
            Spake2State::Begin => {
                if is_app {
                    self.rx_counter += 1;
                    if let Some(mut hello) = Self::probe_for_client_hello_struct(
                        &self.cfg,
                        &data.as_ref()[TLS_HEADER_LEN..],
                    )
                        .await
                    {
                        // Reject a stale or already-seen hello *here*, before any
                        // state changes, so a replay is indistinguishable from a
                        // record that was never a hello at all: we fall through
                        // and keep proxying to the cover site. Anything that
                        // aborted or answered differently would hand a DPI box
                        // exactly the oracle this check exists to deny.
                        if let Some(guard) = self.cfg.replay_guard.as_ref() {
                            if !guard.accept(&hello.nonce, hello.current_time) {
                                dbg_log!(
                                    "[FakeCodec DEBUG] on_server_side_remote_packet: hello rejected by replay guard, continuing as cover traffic"
                                );
                                return Some(data);
                            }
                        }

                        self.transcript.client_auth = hello.auth_data.clone();
                        self.transcript.login = hello.login.as_bytes().to_vec();
                        self.transcript.server_id = self.cfg.server_id.clone();
                        self.transcript.nonce = hello.nonce.clone();
                        self.transcript.current_time = hello.current_time;

                        let data = mem::replace(&mut hello.original_packet, vec![]);
                        self.state = FirstPartNegotiated(FirstPartSpake2::Server(hello));
                        self.tx_counter = 0;
                        return Some(Bytes::from(data));
                    }
                }
                Some(data)
            }
            Spake2State::FirstPartNegotiated(_fp) => {
                if is_app {
                    self.rx_counter += 1;
                }
                Some(data)
            }
            Spake2State::SecondPartNegotiated(_) => {
                if is_app {
                    self.rx_counter += 1;
                    if self
                        .probe_for_client_begin(&data.as_ref()[TLS_HEADER_LEN..])
                        .await
                    {
                        return None;
                    }
                }
                Some(data)
            }
        }
    }

    async fn on_client_side_local_packet(&mut self, data: Bytes) -> Option<Bytes> {
        let is_app = is_application_data(&data);
        match &self.state {
            Spake2State::Begin => {
                // `>=`, not `==`: target_packet comes from a pattern recorded in a
                // different session, so this session may skip past it. An equality
                // test would then never fire and the handshake would stall silently.
                if is_app && self.tx_counter >= self.target_packet {
                    self.tx_counter += 1;
                    let res = Self::inject_client_message(&self.cfg, data.to_vec()).await?;
                    self.transcript = res.2;
                    self.state =
                        Spake2State::FirstPartNegotiated(FirstPartSpake2::Client(Some(res.1)));
                    if self.base_tls_header.is_none() {
                        self.base_tls_header = Some(data.as_ref()[..TLS_HEADER_LEN].to_vec());
                    }
                    Some(Bytes::from(res.0))
                } else {
                    if is_app {
                        self.tx_counter += 1;
                        if self.base_tls_header.is_none() {
                            self.base_tls_header = Some(data.as_ref()[..TLS_HEADER_LEN].to_vec());
                        }
                    }
                    Some(data)
                }
            }
            Spake2State::FirstPartNegotiated(_spake) => {
                if is_app {
                    self.tx_counter += 1;
                }
                Some(data)
            }
            Spake2State::SecondPartNegotiated(_shared) => {
                if is_app {
                    self.tx_counter += 1;
                }
                Some(data)
            }
        }
    }

    async fn on_client_side_remote_packet(&mut self, data: Bytes) -> Option<Bytes> {
        let is_app = is_application_data(&data);
        match &mut self.state {
            Spake2State::Begin => {
                if is_app {
                    self.rx_counter += 1;
                }
                Some(data)
            }
            Spake2State::FirstPartNegotiated(spake) => {
                if is_app {
                    self.rx_counter += 1;
                    if let Some(hello) = Self::probe_for_server_hello_struct(
                        &self.cfg,
                        &data.as_ref()[TLS_HEADER_LEN..],
                    )
                        .await
                    {
                        let FirstPartSpake2::Client(spake) = spake else {
                            return None;
                        };
                        let result = spake.take()?.finish(hello.auth_data.as_slice()).ok()?;
                        // Completes the transcript on this side; the client half
                        // was recorded when the hello was built.
                        self.transcript.server_auth = hello.auth_data;
                        self.state = Spake2State::SecondPartNegotiated(result);
                        return Some(Bytes::from(hello.original_packet));
                    }
                }
                Some(data)
            }
            Spake2State::SecondPartNegotiated(_) => {
                if is_app {
                    self.rx_counter += 1;
                }
                Some(data)
            }
        }
    }

    async fn inject_client_message(
        cfg: &FakeCodecCfg,
        original_packet: Vec<u8>,
    ) -> Option<(Vec<u8>, Spake2<Ed25519Group>, HandshakeTranscript)> {
        dbg_log!("[FakeCodec DEBUG] inject_client_message: Starting");
        let mut tls_header = (&original_packet[..TLS_HEADER_LEN]).to_vec();
        let mut client_message = ClientHelloStruct::new();
        client_message.original_packet = original_packet;

        client_message.current_time = ReplayGuard::current_time_ms();
        client_message.nonce = generate_random_u8_vec(HELLO_NONCE_LEN);

        let cred_provider = match cfg.credentials.clone() {
            CredentialsSide::Server(_) => {
                dbg_log!(
                    "[FakeCodec DEBUG] inject_client_message: Invalid credentials side (Server)"
                );
                return None;
            }
            CredentialsSide::Client(cred) => cred,
        };

        let creds = match cred_provider.get_client_credentials().await {
            Some(c) => c,
            None => {
                dbg_log!(
                    "[FakeCodec DEBUG] inject_client_message: Failed to get client credentials"
                );
                return None;
            }
        };


        if creds.0.len() > MAX_LOGIN_LEN {
            dbg_log!(
                "[FakeCodec DEBUG] inject_client_message: login of {} bytes exceeds max {}",
                creds.0.len(),
                MAX_LOGIN_LEN
            );
            return None;
        }
        client_message.login = match String::from_utf8(creds.0.clone()) {
            Ok(login) => login,
            Err(_) => {
                dbg_log!(
                    "[FakeCodec DEBUG] inject_client_message: login is not valid UTF-8; the SPAKE2 identity binds raw bytes, so this would diverge silently"
                );
                return None;
            }
        };

        let res = match Self::make_spake2_client_initial(cred_provider, cfg.server_id.as_slice())
            .await
        {
            Some(r) => r,
            None => {
                dbg_log!(
                    "[FakeCodec DEBUG] inject_client_message: Failed to make spake2 client initial"
                );
                return None;
            }
        };
        client_message.auth_data = res.0;

        let transcript = HandshakeTranscript {
            client_auth: client_message.auth_data.clone(),
            server_auth: Vec::new(),
            login: client_message.login.as_bytes().to_vec(),
            server_id: cfg.server_id.clone(),
            nonce: client_message.nonce.clone(),
            current_time: client_message.current_time,
        };

        let data = match s_type::to_bytes(&client_message) {
            Some(d) => d.to_vec(),
            None => {
                dbg_log!(
                    "[FakeCodec DEBUG] inject_client_message: Failed to serialize client message"
                );
                return None;
            }
        };

        let container = PacketContainer::wrap_existing_data(
            data,
            &cfg.pattern,
            cfg.max_adjusted_padding_derivation_percent,
            cfg.message_padding_size.clone(),
            HANDSHAKE_WIRE_OVERHEAD,
        );

        let data = match s_type::to_bytes(&container) {
            Some(d) => d.to_vec(),
            None => {
                dbg_log!(
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
                dbg_log!("[FakeCodec DEBUG] inject_client_message: Failed to encrypt message");
                return None;
            }
        };

        // Bound before narrowing: casting first lets a body of 2^16 + n wrap to
        // n, pass the check, and write a truncated length into the record header.
        if msg.len() > TLS_MAX_RECORD_LEN {
            dbg_log!(
                "[FakeCodec DEBUG] inject_client_message: Record length {} exceeds max {}",
                msg.len(),
                TLS_MAX_RECORD_LEN
            );
            return None;
        }
        let record_len = msg.len() as u16;
        let record_len_bytes = record_len.to_be_bytes();
        tls_header[3] = record_len_bytes[0];
        tls_header[4] = record_len_bytes[1];
        tls_header.append(&mut msg);
        dbg_log!(
            "[FakeCodec DEBUG] inject_client_message: Success, final packet len: {}",
            tls_header.len()
        );
        Some((tls_header, res.1, transcript))
    }

    async fn inject_server_message(
        cfg: &FakeCodecCfg,
        client_hello: &ClientHelloStruct,
        original_packet: Vec<u8>,
    ) -> Option<(Vec<u8>, Spake2<Ed25519Group>, Vec<u8>)> {

        dbg_log!("[FakeCodec DEBUG] inject_server_message: Starting");
        let mut tls_header = (&original_packet[..TLS_HEADER_LEN]).to_vec();

        if client_hello.login.len() > MAX_LOGIN_LEN {
            dbg_log!(
                "[FakeCodec DEBUG] inject_server_message: login of {} bytes exceeds max {}",
                client_hello.login.len(),
                MAX_LOGIN_LEN
            );
            return None;
        }

        let mut server_msg = ServerHelloStruct::new();
        server_msg.original_packet = original_packet;

        let cred_provider = match cfg.credentials.clone() {
            CredentialsSide::Server(cred) => Some(cred),
            CredentialsSide::Client(_) => {
                dbg_log!(
                    "[FakeCodec DEBUG] inject_server_message: Invalid credentials side (Client)"
                );
                None
            }
        }?;

        let server_auth = match Self::make_spake2_server_initial(
            cred_provider,
            cfg.server_id.as_slice(),
            client_hello.login.clone(),
        client_hello.current_time)
            .await
        {
            Some(sa) => sa,
            None => {
                dbg_log!(
                    "[FakeCodec DEBUG] inject_server_message: Failed to make spake2 server initial"
                );
                return None;
            }
        };

        server_msg.auth_data = server_auth.0;
        let server_auth_data = server_msg.auth_data.clone();

        let data = match s_type::to_bytes(&server_msg) {
            Some(d) => d.to_vec(),
            None => {
                dbg_log!(
                    "[FakeCodec DEBUG] inject_server_message: Failed to serialize server message"
                );
                return None;
            }
        };

        let container = PacketContainer::wrap_existing_data(
            data,
            &cfg.pattern,
            cfg.max_adjusted_padding_derivation_percent,
            cfg.message_padding_size.clone(),
            HANDSHAKE_WIRE_OVERHEAD,
        );

        let data = match s_type::to_bytes(&container) {
            Some(d) => d.to_vec(),
            None => {
                dbg_log!(
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
                dbg_log!("[FakeCodec DEBUG] inject_server_message: Failed to encrypt message");
                return None;
            }
        };

        // Bound before narrowing: see inject_client_message.
        if msg.len() > TLS_MAX_RECORD_LEN {
            dbg_log!(
                "[FakeCodec DEBUG] inject_server_message: Record length {} exceeds max {}",
                msg.len(),
                TLS_MAX_RECORD_LEN
            );
            return None;
        }
        let record_len = msg.len() as u16;
        let record_len_bytes = record_len.to_be_bytes();
        tls_header[3] = record_len_bytes[0];
        tls_header[4] = record_len_bytes[1];
        tls_header.append(&mut msg);
        dbg_log!(
            "[FakeCodec DEBUG] inject_server_message: Success, final packet len: {}",
            tls_header.len()
        );
        Some((tls_header, server_auth.1, server_auth_data))
    }

    pub(crate) async fn make_client_begin_msg(
        cfg: &FakeCodecCfg,
        mut base_tls_header: Vec<u8>,
        confirm: &[u8],
    ) -> Option<Vec<u8>> {
        let mut msg = ClientBeginStruct::new();
        msg.confirm = confirm.to_vec();
        let data = s_type::to_bytes(&msg)?.to_vec();

        let container = PacketContainer::wrap_existing_data(
            data,
            &cfg.pattern,
            cfg.max_adjusted_padding_derivation_percent,
            cfg.message_padding_size.clone(),
            HANDSHAKE_WIRE_OVERHEAD,
        );

        let data = match s_type::to_bytes(&container) {
            Some(d) => d.to_vec(),
            None => {
                dbg_log!(
                    "[FakeCodec DEBUG] inject_client_message: Failed to serialize client message"
                );
                return None;
            }
        };

        let mut data = match Self::encrypt_message_with_pub_key(
            data.as_slice(),
            cfg.public_password.as_slice(),
        )
            .await
        {
            Some(d) => d,
            None => {
                dbg_log!("[FakeCodec DEBUG] make_client_begin_msg: Encryption failed");
                return None;
            }
        };
        if data.len() > TLS_MAX_RECORD_LEN {
            dbg_log!(
                "[FakeCodec DEBUG] begin message: Record length {} exceeds max {}",
                data.len(),
                TLS_MAX_RECORD_LEN
            );
            return None;
        }
        let record_len = data.len() as u16;
        let record_len_bytes = record_len.to_be_bytes();
        base_tls_header[3] = record_len_bytes[0];
        base_tls_header[4] = record_len_bytes[1];
        base_tls_header.append(&mut data);
        Some(base_tls_header)
    }


    pub(crate) async fn make_server_begin_msg(
        cfg: &FakeCodecCfg,
        mut base_tls_header: Vec<u8>,
        confirm: &[u8],
    ) -> Option<Vec<u8>> {
        let mut msg = ServerBeginStruct::new();
        msg.confirm = confirm.to_vec();
        let data = s_type::to_bytes(&msg)?.to_vec();

        let container = PacketContainer::wrap_existing_data(
            data,
            &cfg.pattern,
            cfg.max_adjusted_padding_derivation_percent,
            cfg.message_padding_size.clone(),
            HANDSHAKE_WIRE_OVERHEAD,
        );

        let data = match s_type::to_bytes(&container) {
            Some(d) => d.to_vec(),
            None => {
                dbg_log!(
                    "[FakeCodec DEBUG] inject_client_message: Failed to serialize client message"
                );
                return None;
            }
        };

        let mut data = match Self::encrypt_message_with_pub_key(
            data.as_slice(),
            cfg.public_password.as_slice(),
        )
            .await
        {
            Some(d) => d,
            None => {
                dbg_log!("[FakeCodec DEBUG] make_client_begin_msg: Encryption failed");
                return None;
            }
        };
        // Bound before narrowing: see inject_client_message.
        if data.len() > TLS_MAX_RECORD_LEN {
            dbg_log!(
                "[FakeCodec DEBUG] begin message: Record length {} exceeds max {}",
                data.len(),
                TLS_MAX_RECORD_LEN
            );
            return None;
        }
        let record_len = data.len() as u16;
        let record_len_bytes = record_len.to_be_bytes();
        base_tls_header[3] = record_len_bytes[0];
        base_tls_header[4] = record_len_bytes[1];
        base_tls_header.append(&mut data);
        Some(base_tls_header)
    }


    async fn probe_for_server_begin(&self, packet: &[u8]) -> bool {
        let Some(msg) =
            Self::decrypt_message_with_pub_key(packet, self.cfg.public_password.as_slice()).await
        else {
            return false;
        };
        let Ok(base) = s_type::access::<PacketContainer>(msg.as_slice()) else {
            return false;
        };
        let Ok(open) = s_type::access::<ServerBeginStruct>(base.packet.as_slice()) else {
            return false;
        };
        if !ServerBeginStruct::validate_arc(open) {
            return false;
        }
        if !self.verify_peer_confirm(open.confirm.as_ref()) {
            dbg_log!(
                "[FakeCodec DEBUG] probe_for_server_begin: key confirmation failed; treating as cover traffic"
            );
            return false;
        }
        dbg_log!("[FakeCodec DEBUG] probe_for_server_begin: confirmed");
        true
    }


    /// Recognise a `ClientBegin` **and** verify its key-confirmation tag.
    ///
    /// This is the check that stops a probe holding the public password from
    /// driving the server out of cover-traffic mode with a forged handshake —
    /// and with it, the username oracle that behaviour would expose.
    async fn probe_for_client_begin(&self, packet: &[u8]) -> bool {
        let Some(msg) =
            Self::decrypt_message_with_pub_key(packet, self.cfg.public_password.as_slice()).await
        else {
            return false;
        };
        let Ok(base) = s_type::access::<PacketContainer>(msg.as_slice()) else {
            return false;
        };
        let Ok(open) = s_type::access::<ClientBeginStruct>(base.packet.as_slice()) else {
            return false;
        };
        if !ClientBeginStruct::validate_arc(open) {
            return false;
        }
        if !self.verify_peer_confirm(open.confirm.as_ref()) {
            dbg_log!(
                "[FakeCodec DEBUG] probe_for_client_begin: key confirmation failed; treating as cover traffic"
            );
            return false;
        }
        dbg_log!("[FakeCodec DEBUG] probe_for_client_begin: confirmed");
        true
    }

    async fn probe_for_server_hello_struct(
        cfg: &FakeCodecCfg,
        packet: &[u8],
    ) -> Option<ServerHelloStruct> {
        dbg_log!(
            "[FakeCodec DEBUG] probe_for_server_hello_struct: Starting, packet len: {}",
            packet.len()
        );
        if let Some(msg) =
            Self::decrypt_message_with_pub_key(&packet, cfg.public_password.as_slice()).await
        {
            if let Ok(base) = s_type::access::<PacketContainer>(msg.as_slice()) {
                if let Ok(open) = s_type::access::<ServerHelloStruct>(base.packet.as_slice()) {
                    if ServerHelloStruct::validate_arc(open) {
                        dbg_log!("[FakeCodec DEBUG] probe_for_server_hello_struct: Success");
                        let _ = open;
                        return Some(s_type::from_slice(base.packet.as_slice()).unwrap());
                    } else {
                        dbg_log!(
                            "[FakeCodec DEBUG] probe_for_server_hello_struct: Validation failed"
                        );
                    }
                } else {
                    dbg_log!("[FakeCodec DEBUG] probe_for_server_hello_struct: Access failed");
                }
            }
        } else {
            dbg_log!("[FakeCodec DEBUG] probe_for_server_hello_struct: Decryption failed");
        }
        None
    }

    async fn probe_for_client_hello_struct(
        cfg: &FakeCodecCfg,
        data: &[u8],
    ) -> Option<ClientHelloStruct> {
        dbg_log!(
            "[FakeCodec DEBUG] probe_for_client_hello_struct: Starting, data len: {}",
            data.len()
        );
        if let Some(msg) =
            Self::decrypt_message_with_pub_key(data, cfg.public_password.as_slice()).await
        {
            if let Ok(base) = s_type::access::<PacketContainer>(msg.as_slice()) {
                if let Ok(open) = s_type::access::<ClientHelloStruct>(base.packet.as_slice()) {
                    if ClientHelloStruct::validate_arc(open) {
                        dbg_log!("[FakeCodec DEBUG] probe_for_client_hello_struct: Success");
                        let _ = open;
                        return Some(s_type::from_slice(base.packet.as_slice()).unwrap());
                    } else {
                        dbg_log!(
                            "[FakeCodec DEBUG] probe_for_client_hello_struct: Validation failed"
                        );
                    }
                } else {
                    dbg_log!("[FakeCodec DEBUG] probe_for_client_hello_struct: Access failed");
                }
            }
        } else {
            dbg_log!("[FakeCodec DEBUG] probe_for_client_hello_struct: Decryption failed");
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
                dbg_log!(
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
        dbg_log!("[FakeCodec DEBUG] make_spake2_client_initial: SPAKE2 start_a successful");
        Some((outbound_msg, spake))
    }

    async fn make_spake2_server_initial(
        cred_provider: Arc<dyn ServerCredentialProvider>,
        server_id: &[u8],
        client_id: String,
        time_in_message: u64
    ) -> Option<(Vec<u8>, Spake2<Ed25519Group>)> {
        let password = match cred_provider.get_client_password(&client_id, time_in_message).await {
            Some(p) => p,
            None => {
                dbg_log!(
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
        dbg_log!("[FakeCodec DEBUG] make_spake2_server_initial: SPAKE2 start_b successful");
        Some((outbound_msg, spake))
    }

    async fn encrypt_message_with_pub_key(msg: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        let res = aes256_gcm_encrypt(key, msg);
        if res.is_err() {
            dbg_log!(
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
            dbg_log!(
                "[FakeCodec DEBUG] decrypt_message_with_pub_key: aes256_gcm_decrypt failed: {:?}",
                res.err().unwrap()
            );
            return None;
        }
        res.ok()
    }

    fn select_packet_from_pattern(
        pattern: &ConnectionPattern,
        start_index: usize,
        end_offset: usize,
    ) -> usize {
        let ordered_packets = pattern.order();
        if ordered_packets.is_empty() {
            dbg_log!("[FakeCodec DEBUG] select_packet_from_pattern: pattern.order() is empty!");
            return start_index + 1;
        }

        let start = pattern.overall_idx_to_order_idx(start_index);
        let end = pattern.overall_idx_to_order_idx_backwards(end_offset);

        if start >= end {
            dbg_log!(
                "[FakeCodec DEBUG] select_packet_from_pattern: Invalid range ({start}..{end}), falling back"
            );
            return start_index + 1;
        }

        let mut attempts = 10;
        let mut rng = rand::rng();
        loop {
            let order_idx = rng.random_range(start..end);

            if ordered_packets[order_idx].repeat_times == 1 || attempts <= 1 {
                return pattern
                    .order_idx_to_overall_idx(order_idx)
                    .max(start_index + 1);
            }
            attempts -= 1;
        }
    }

    pub fn state(&self) -> &Spake2State {
        &self.state
    }
}

const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

pub fn is_application_data(data: &[u8]) -> bool {
    data.first() == Some(&TLS_CONTENT_TYPE_APPLICATION_DATA)
}