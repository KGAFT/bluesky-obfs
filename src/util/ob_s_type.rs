use crate::strategy::{ArchivedConnectionPattern, ConnectionPattern};
use crate::util::ob_s_type::ObSType::{ClientBegin, ClientHello, PacketContainerB, PacketContainerE, ServerBegin, ServerHello};
use crate::util::rand_util::generate_random_u8_vec;
use num_enum::TryFromPrimitive;
use rand::Rng;
use rkyv::{Archive, Deserialize, Serialize};
use std::any::{Any, TypeId};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::ops::Range;
use tfserver::structures::s_type;
use tfserver::structures::s_type::{StrongType, StructureType};
use tfserver::{impl_strong_type, impl_structure_type};
use tokio_util::bytes::Bytes;

#[repr(u8)]
#[derive(
    Serialize,
    Deserialize,
    PartialEq,
    Clone,
    Hash,
    Eq,
    TryFromPrimitive,
    Copy,
    Debug,
    Archive,
    Default,
)]
pub enum ObSType {
    #[default]
    ClientHello,
    ServerHello,
    ClientBegin,
    ConnectionPatternE,
    PacketContainerE,
    PacketContainerB,
    ServerBegin,
}

impl_structure_type!(
    ObSType, ArchivedObSType,
    ClientHello => (ClientHelloStruct, ArchivedClientHelloStruct),
    ServerHello => (ServerHelloStruct, ArchivedServerHelloStruct),
    ClientBegin => (ClientBeginStruct, ArchivedClientBeginStruct),
    ConnectionPatternE => (ConnectionPattern, ArchivedConnectionPattern),
    PacketContainerE => (PacketContainer, ArchivedPacketContainer),
    PacketContainerB => (PacketContainerBytes, ArchivedPacketContainerBytes),
    ServerBegin => (ServerBeginStruct, ArchivedServerBeginStruct),
);

impl_strong_type!(
    ClientHelloStruct => ArchivedClientHelloStruct,
    ServerHelloStruct => ArchivedServerHelloStruct,
    ClientBeginStruct => ArchivedClientBeginStruct,
    PacketContainer => ArchivedPacketContainer,
    PacketContainerBytes => ArchivedPacketContainerBytes,
    ServerBeginStruct => ArchivedServerBeginStruct,
);

pub const CLIENT_VALIDATE_MSG: &str = "client hello message!";
pub const SERVER_VALIDATE_MSG: &str = "server hello message!";

pub const CLIENT_BEGIN: &str = "client begin!";
pub const SERVER_BEGIN: &str = "server begin!";
#[derive(Serialize, Deserialize, Debug, Archive)]
pub struct PacketContainer {
    pub padding: Vec<u8>,
    pub packet: Vec<u8>,
    pub s_type: ObSType,
}

impl PacketContainer {
    pub fn new() -> Self {
        Self {
            padding: vec![],
            packet: vec![],
            s_type: PacketContainerE,
        }
    }

    pub fn new_with_specified_padding_size(padding_size: usize) -> Self {
        let padding = generate_random_u8_vec(padding_size);
        let mut res = Self::new();
        res.padding = padding;
        res
    }

    pub fn new_with_random_padding(padding_size: Range<usize>) -> Self {
        let mut res = Self::new();
        let mut rng = rand::rng();
        let len = rng.random_range(padding_size.clone());
        res.padding = generate_random_u8_vec(len);
        res
    }

    /// Serialization overhead the container itself adds, measured rather than
    /// assumed.
    ///
    /// rkyv's framing here is exactly linear in the two vector lengths — each
    /// extra padding byte costs exactly one serialized byte — but the constant
    /// is an implementation detail of the rkyv version in use, so derive it from
    /// a zero-padding probe instead of baking a number in that a dependency bump
    /// could silently invalidate.
    fn container_overhead(packet_len: usize) -> Option<usize> {
        let mut probe = Self::new();
        probe.packet = vec![0u8; packet_len];
        s_type::to_bytes(&probe)?.len().checked_sub(packet_len)
    }

    /// Wrap `data` and pad so the **finished record on the wire** lands on a
    /// size the cover site actually emits.
    ///
    /// `wire_overhead` is everything the caller will add after serializing this
    /// container — for the handshake messages that is the AEAD nonce and tag
    /// plus the TLS record header.
    ///
    /// This used to size the padding against `data.len()`, the inner struct,
    /// ignoring the container framing, the AEAD expansion and the record header.
    /// Every handshake message therefore landed a fixed ~50 bytes above the size
    /// the pattern had chosen — the same constant-offset tell that `encode` had,
    /// just on a different path.
    pub fn wrap_existing_data(
        data: Vec<u8>,
        pattern: &ConnectionPattern,
        max_derivation_percent: f64,
        padding_size: Range<usize>,
        wire_overhead: usize,
    ) -> Self {
        let overhead = Self::container_overhead(data.len()).unwrap_or(0) + wire_overhead;
        let min_wire_len = data.len() + overhead;

        let padding_len =
            match pattern.select_packet_size_randomized(min_wire_len, max_derivation_percent) {
                Some(target_wire_len) => {
                    dbg_log!(
                        "Targeting wire size {} for base size {}",
                        target_wire_len,
                        data.len()
                    );
                    // Candidates are always >= min_wire_len, so this cannot wrap.
                    target_wire_len - min_wire_len
                }
                None => rand::rng().random_range(padding_size),
            };

        let mut container = Self::new_with_specified_padding_size(padding_len);
        container.packet = data;
        container
    }
}


#[derive(Serialize, Deserialize, Debug, Archive)]
pub struct PacketContainerBytes {
    pub padding: Vec<u8>,
    pub packet: Bytes,
    pub s_type: ObSType,
}

impl PacketContainerBytes {
    pub fn new() -> Self {
        Self {
            padding: vec![],
            packet: Bytes::new(),
            s_type: PacketContainerB,
        }
    }

    pub fn new_with_specified_padding_size(padding_size: usize) -> Self {
        let padding = generate_random_u8_vec(padding_size);
        let mut res = Self::new();
        res.padding = padding;
        res
    }

    pub fn new_with_random_padding(padding_size: Range<usize>) -> Self {
        let mut res = Self::new();
        let mut rng = rand::rng();
        let len = rng.random_range(padding_size.clone());
        res.padding = generate_random_u8_vec(len);
        res
    }

    /// See [`PacketContainer::container_overhead`].
    fn container_overhead(packet_len: usize) -> Option<usize> {
        let mut probe = Self::new();
        probe.packet = Bytes::from(vec![0u8; packet_len]);
        s_type::to_bytes(&probe)?.len().checked_sub(packet_len)
    }

    /// See [`PacketContainer::wrap_existing_data`].
    pub fn wrap_existing_data(
        data: Bytes,
        pattern: &ConnectionPattern,
        max_derivation_percent: f64,
        padding_size: Range<usize>,
        wire_overhead: usize,
    ) -> Self {
        let overhead = Self::container_overhead(data.len()).unwrap_or(0) + wire_overhead;
        let min_wire_len = data.len() + overhead;

        let padding_len =
            match pattern.select_packet_size_randomized(min_wire_len, max_derivation_percent) {
                Some(target_wire_len) => target_wire_len - min_wire_len,
                None => rand::rng().random_range(padding_size),
            };

        let mut container = Self::new_with_specified_padding_size(padding_len);
        container.packet = data;
        container
    }
}

#[derive(Serialize, Deserialize, Debug, Archive)]
pub struct ClientHelloStruct {
    pub s_type: ObSType,
    pub validate_msg: String,
    pub login: String,
    pub auth_data: Vec<u8>,
    pub original_packet: Vec<u8>,
    /// Client wall clock in milliseconds when this hello was built. Bounds how
    /// long a recording of this record stays replayable.
    pub current_time: u64,
    /// Single-use random value. Together with `current_time` this makes each
    /// hello usable exactly once inside the server's replay window; see
    /// [`crate::util::replay_guard::ReplayGuard`].
    pub nonce: Vec<u8>,
}

impl ClientHelloStruct {
    pub fn new() -> Self {
        Self {
            s_type: ClientHello,
            login: String::new(),
            auth_data: vec![],
            original_packet: vec![],
            validate_msg: CLIENT_VALIDATE_MSG.to_string(),
            current_time: 0,
            nonce: vec![],
        }
    }

    pub fn validate(&self) -> bool {
        self.validate_msg.eq(CLIENT_VALIDATE_MSG)
    }

    pub fn validate_arc(data: &ArchivedClientHelloStruct) -> bool {
        data.validate_msg.eq(CLIENT_VALIDATE_MSG)
    }
}

#[derive(Serialize, Deserialize, Debug, Archive)]
pub struct ServerHelloStruct {
    pub s_type: ObSType,
    pub validate_msg: String,
    pub auth_data: Vec<u8>,
    pub original_packet: Vec<u8>,
}

impl ServerHelloStruct {
    pub fn new() -> Self {
        Self {
            s_type: ServerHello,
            auth_data: vec![],
            original_packet: vec![],
            validate_msg: SERVER_VALIDATE_MSG.to_string(),
        }
    }

    pub fn validate(&self) -> bool {
        self.validate_msg.eq(SERVER_VALIDATE_MSG)
    }
    pub fn validate_arc(data: &ArchivedServerHelloStruct) -> bool {
        data.validate_msg.eq(SERVER_VALIDATE_MSG)
    }
}
#[derive(Serialize, Deserialize, Debug, Archive)]
pub struct ClientBeginStruct {
    pub s_type: ObSType,
    pub validate_msg: String,
    /// Key-confirmation tag proving this peer really derived the SPAKE2 shared
    /// secret — i.e. that it knew the password.
    ///
    /// Without this, `finish()` succeeds on any well-formed group element, so a
    /// probe holding the (per-server, but extractable) public password could
    /// drive the server through the whole handshake into tunnel mode with no
    /// password at all. That is not a confidentiality break — it can't read
    /// traffic — but it makes "did this server leave cover-traffic mode?" an
    /// observable, and therefore a username oracle.
    pub confirm: Vec<u8>,
}

impl ClientBeginStruct {
    pub fn new() -> Self {
        Self {
            s_type: ClientBegin,
            validate_msg: CLIENT_BEGIN.to_string(),
            confirm: vec![],
        }
    }
    pub fn validate(&self) -> bool {
        self.validate_msg.eq(CLIENT_BEGIN)
    }
    pub fn validate_arc(data: &ArchivedClientBeginStruct) -> bool {
        data.validate_msg.eq(CLIENT_BEGIN)
    }
}

#[derive(Serialize, Deserialize, Debug, Archive)]
pub struct ServerBeginStruct {
    pub s_type: ObSType,
    pub validate_msg: String,
    /// Server-side key-confirmation tag. Mirror of
    /// [`ClientBeginStruct::confirm`], so the client can tell a real server from
    /// a replayed `ServerHello` + `ServerBegin` pair.
    pub confirm: Vec<u8>,
}

impl ServerBeginStruct {
    pub fn new() -> Self {
        Self {
            s_type: ServerBegin,
            validate_msg: SERVER_BEGIN.to_string(),
            confirm: vec![],
        }
    }
    pub fn validate(&self) -> bool {
        self.validate_msg.eq(SERVER_BEGIN)
    }
    pub fn validate_arc(data: &ArchivedServerBeginStruct) -> bool {
        data.validate_msg.eq(SERVER_BEGIN)
    }
}

