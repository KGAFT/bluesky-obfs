use std::mem;
use std::sync::Arc;
use rand::Rng;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use tfserver::structures::s_type;
use tokio_util::bytes::Bytes;
use crate::codec::fake_codec::{ClientCredentialProvider, CredentialsSide, FakeCodecCfg, ServerCredentialProvider};
use crate::codec::tls_codec::{TLS_HEADER_LEN, TLS_MAX_RECORD_LEN};
use crate::strategy::ConnectionPattern;
use crate::util::crypt_util::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::util::ob_s_type::{ClientBeginStruct, ClientHelloStruct, ServerHelloStruct};
use crate::util::spake2_injector::Spake2State::FirstPartNegotiated;

pub enum FirstPartSpake2{
    Client(Option<Spake2<Ed25519Group>>),
    Server(ClientHelloStruct),
}

pub enum Spake2State{
    Begin,
    FirstPartNegotiated(FirstPartSpake2),
    SecondPartNegotiated(Vec<u8>),
}

pub struct Spake2Injector {
    state: Spake2State,
    tx_counter: usize,
    rx_counter: usize,
    cfg: FakeCodecCfg,
    target_packet: usize
}

impl Spake2Injector {
    pub fn new( cfg: FakeCodecCfg) -> Self {
        let offsets = match cfg.credentials{
            CredentialsSide::Server(_) => {(0usize, 1usize)}
            CredentialsSide::Client(_) => {(1,1)}
        };
        let target_packet = Self::select_packet_from_pattern(&cfg.pattern, offsets.0, offsets.1);

        Self{state: Spake2State::Begin, cfg, tx_counter: 0, rx_counter: 0, target_packet}
    }

    pub async fn on_remote_packet(&mut self, data: Bytes) -> Option<Bytes> {
        match &self.cfg.credentials{
            CredentialsSide::Server(_) => {self.on_server_side_remote_packet(data).await},
            CredentialsSide::Client(_) => {
                self.on_client_side_remote_packet(data).await
            }
        }
    }

    pub async fn on_local_packet(&mut self, data: Bytes) -> Option<Bytes> {
        match &self.cfg.credentials{
            CredentialsSide::Server(_) => {self.on_server_side_local_packet(data).await},
            CredentialsSide::Client(_) => {
                self.on_client_side_local_packet(data).await
            }
        }
    }



    async fn on_server_side_local_packet(&mut self, data: Bytes) -> Option<Bytes> {
        let is_app = is_application_data(&data);
        match &self.state {
            Spake2State::Begin => {
                if is_app { self.tx_counter += 1; }
                Some(data)
            }
            Spake2State::FirstPartNegotiated(fp) => {
                if is_app && self.tx_counter == self.target_packet {
                    self.tx_counter += 1;
                    match fp {
                        FirstPartSpake2::Client(_) => None,
                        FirstPartSpake2::Server(hello) => {
                            let res = Self::inject_server_message(&self.cfg, hello, data.to_vec()).await?;
                            let finished = res.1.finish(hello.auth_data.as_slice()).ok()?;
                            self.state = Spake2State::SecondPartNegotiated(finished);
                            Some(Bytes::from(res.0))
                        }
                    }
                } else {
                    if is_app { self.tx_counter += 1; }
                    Some(data)
                }
            }
            Spake2State::SecondPartNegotiated(_) => {
                if is_app { self.tx_counter += 1; }
                Some(data)
            }
        }
    }

    async fn on_server_side_remote_packet(&mut self, data: Bytes) -> Option<Bytes> {
        let is_app = is_application_data(&data);
        match &self.state {
            Spake2State::Begin => {
                if is_app {
                    self.rx_counter += 1;
                    if let Some(mut hello) = Self::probe_for_client_hello_struct(&self.cfg, &data.as_ref()[TLS_HEADER_LEN..]).await {
                        let data = mem::replace(&mut hello.original_packet, vec![]);
                        self.state = FirstPartNegotiated(FirstPartSpake2::Server(hello));
                        self.target_packet = Self::select_packet_from_pattern(&self.cfg.pattern, self.tx_counter, 1)
                            .max(self.tx_counter + 1);
                        return Some(Bytes::from(data));
                    }
                }
                Some(data)
            }
            Spake2State::FirstPartNegotiated(_fp) => {
                if is_app { self.rx_counter += 1; }
                Some(data)
            }
            Spake2State::SecondPartNegotiated(_) => {
                if is_app {
                    self.rx_counter += 1;
                    if Self::probe_for_client_begin(&self.cfg, &data.as_ref()[TLS_HEADER_LEN..]).await {
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
                if is_app && self.tx_counter == self.target_packet {
                    self.tx_counter += 1;
                    let res = Self::inject_client_message(&self.cfg, data.to_vec()).await?;
                    self.state = Spake2State::FirstPartNegotiated(FirstPartSpake2::Client(Some(res.1)));
                    Some(Bytes::from(res.0))
                } else {
                    if is_app { self.tx_counter += 1; }
                    Some(data)
                }
            }
            Spake2State::FirstPartNegotiated(_spake) => {
                if is_app { self.tx_counter += 1; }
                Some(data)
            }
            Spake2State::SecondPartNegotiated(_shared) => {
                if is_app { self.tx_counter += 1; }
                Some(data)
            }
        }
    }

    async fn on_client_side_remote_packet(&mut self, data: Bytes) -> Option<Bytes> {
        let is_app = is_application_data(&data);
        match &mut self.state {
            Spake2State::Begin => {
                if is_app { self.rx_counter += 1; }
                Some(data)
            }
            Spake2State::FirstPartNegotiated(spake) => {
                if is_app {
                    self.rx_counter += 1;
                    if let Some(hello) = Self::probe_for_server_hello_struct(&self.cfg, &data.as_ref()[TLS_HEADER_LEN..]).await {
                        return match spake {
                            FirstPartSpake2::Client(spake) => {
                                let result = spake.take()?.finish(hello.auth_data.as_slice()).ok()?;
                                self.state = Spake2State::SecondPartNegotiated(result);
                                Some(Bytes::from(hello.original_packet))
                            }
                            FirstPartSpake2::Server(_) => None,
                        };
                    }
                }
                Some(data)
            }
            Spake2State::SecondPartNegotiated(_) => {
                if is_app { self.rx_counter += 1; }
                Some(data)
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

    pub(crate) async fn make_client_begin_msg(&self, mut base_tls_header: Vec<u8>) -> Option<Vec<u8>> {
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

    fn select_packet_from_pattern(pattern: &ConnectionPattern, start_index: usize, end_offset: usize) -> usize {
        return 3;
        //Still broken
        let mut attempts = 10;
        loop {
            let mut rng = rand::rng();
            let ordered_packets = pattern.order();

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

    pub fn state(&self) -> &Spake2State {
        &self.state
    }
}

const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

pub fn is_application_data(data: &[u8]) -> bool {
    data.first() == Some(&TLS_CONTENT_TYPE_APPLICATION_DATA)
}