use crate::strategy::{ArchivedConnectionPattern, ConnectionPattern};
use crate::util::ob_s_type::ObSType::{ClientBegin, ClientHello, PacketContainerB, PacketContainerE, ServerHello};
use crate::util::rand_util::generate_random_u8_vec;
use num_enum::TryFromPrimitive;
use rand::Rng;
use rkyv::{Archive, Deserialize, Serialize};
use std::any::{Any, TypeId};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::ops::Range;
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
    PacketContainerB
}

impl_structure_type!(
    ObSType, ArchivedObSType,
    ClientHello => (ClientHelloStruct, ArchivedClientHelloStruct),
    ServerHello => (ServerHelloStruct, ArchivedServerHelloStruct),
    ClientBegin => (ClientBeginStruct, ArchivedClientBeginStruct),
    ConnectionPatternE => (ConnectionPattern, ArchivedConnectionPattern),
    PacketContainerE => (PacketContainer, ArchivedPacketContainer),
    PacketContainerB => (PacketContainerBytes, ArchivedPacketContainerBytes)
);

impl_strong_type!(
    ClientHelloStruct => ArchivedClientHelloStruct,
    ServerHelloStruct => ArchivedServerHelloStruct,
    ClientBeginStruct => ArchivedClientBeginStruct,
    PacketContainer => ArchivedPacketContainer,
    PacketContainerBytes => ArchivedPacketContainerBytes
);

pub const CLIENT_VALIDATE_MSG: &str = "client hello message!";
pub const SERVER_VALIDATE_MSG: &str = "server hello message!";

pub const CLIENT_BEGIN: &str = "client begin!";
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

    pub fn wrap_existing_data(
        data: Vec<u8>,
        pattern: &ConnectionPattern,
        max_derivation_percent: f64,
        padding_size: Range<usize>,
    ) -> Self {
        let mut container =
            if let Some(size) = pattern.select_packet_size(data.len(), max_derivation_percent) {
                eprintln!("Found target packet size: {} with base size: {}", size, data.len());
                PacketContainer::new_with_specified_padding_size(size-data.len())
            } else {
                PacketContainer::new_with_random_padding(padding_size)
            };
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

    pub fn wrap_existing_data(
        data: Bytes,
        pattern: &ConnectionPattern,
        max_derivation_percent: f64,
        padding_size: Range<usize>,
    ) -> Self {
        let mut container =
            if let Some(size) = pattern.select_packet_size(data.len(), max_derivation_percent) {
                eprintln!("Found target packet size: {} with base size: {}", size, data.len());
                PacketContainerBytes::new_with_specified_padding_size(size-data.len())
            } else {
                PacketContainerBytes::new_with_random_padding(padding_size)
            };
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
}

impl ClientHelloStruct {
    pub fn new() -> Self {
        Self {
            s_type: ClientHello,
            login: String::new(),
            auth_data: vec![],
            original_packet: vec![],
            validate_msg: CLIENT_VALIDATE_MSG.to_string(),
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
}

impl ClientBeginStruct {
    pub fn new() -> Self {
        Self {
            s_type: ClientBegin,
            validate_msg: CLIENT_BEGIN.to_string(),
        }
    }
    pub fn validate(&self) -> bool {
        self.validate_msg.eq(CLIENT_BEGIN)
    }
    pub fn validate_arc(data: &ArchivedClientBeginStruct) -> bool {
        data.validate_msg.eq(CLIENT_BEGIN)
    }
}
