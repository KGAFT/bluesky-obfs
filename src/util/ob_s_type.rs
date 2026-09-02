use crate::util::ob_s_type::ObSType::{ClientBegin, ClientHello, ServerHello};
use crate::util::rand_util::generate_random_u8_vec;
use num_enum::TryFromPrimitive;
use rand::Rng;
use rkyv::{Archive, Deserialize, Serialize};
use std::any::{Any, TypeId};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::ops::Range;
use tfserver::structures::s_type::{StrongType, StructureType};
use tfserver::{impl_strong_type, impl_structure_type};
use crate::strategy::{ConnectionPattern, ArchivedConnectionPattern};
#[repr(u8)]
#[derive(
    Serialize, Deserialize, PartialEq, Clone, Hash, Eq, TryFromPrimitive, Copy, Debug, Archive, Default)]
pub enum ObSType {
    #[default]
    ClientHello,
    ServerHello,
    ClientBegin,
    ConnectionPatternE
}

impl_structure_type!(
    ObSType, ArchivedObSType,
    ClientHello => (ClientHelloStruct, ArchivedClientHelloStruct),
    ServerHello => (ServerHelloStruct, ArchivedServerHelloStruct),
    ClientBegin => (ClientBeginStruct, ArchivedClientBeginStruct),
    ConnectionPatternE => (ConnectionPattern, ArchivedConnectionPattern)
);

impl_strong_type!(
    ClientHelloStruct => ArchivedClientHelloStruct,
    ServerHelloStruct => ArchivedServerHelloStruct,
    ClientBeginStruct => ArchivedClientBeginStruct
);

pub const CLIENT_VALIDATE_MSG: &str = "client hello message!";
pub const SERVER_VALIDATE_MSG: &str = "server hello message!";

pub const CLIENT_BEGIN: &str = "client begin!";

#[derive(Serialize, Deserialize, Debug, Archive)]
pub struct ClientHelloStruct {
    pub padding_start: Vec<u8>,
    pub s_type: ObSType,
    pub validate_msg: String,
    pub login: String,
    pub auth_data: Vec<u8>,
    pub original_packet: Vec<u8>,
    pub padding_end: Vec<u8>,
}

impl ClientHelloStruct {
    pub fn new() -> Self {
        Self {
            padding_start: vec![],
            padding_end: vec![],
            s_type: ClientHello,
            login: String::new(),
            auth_data: vec![],
            original_packet: vec![],
            validate_msg: CLIENT_VALIDATE_MSG.to_string(),
        }
    }

    pub fn new_with_random_padding(padding_size: Range<usize>) -> Self {
        let mut res = Self::new();
        let mut rng = rand::rng();
        let len1 = rng.random_range(padding_size.clone());
        let len2 = rng.random_range(padding_size);
        res.padding_start = generate_random_u8_vec(len1);
        res.padding_end = generate_random_u8_vec(len2);
        res
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
    pub padding_start: Vec<u8>,
    pub s_type: ObSType,
    pub validate_msg: String,
    pub auth_data: Vec<u8>,
    pub original_packet: Vec<u8>,
    pub padding_end: Vec<u8>,
}

impl ServerHelloStruct {
    pub fn new() -> Self {
        Self {
            padding_start: vec![],
            padding_end: vec![],
            s_type: ServerHello,
            auth_data: vec![],
            original_packet: vec![],
            validate_msg: SERVER_VALIDATE_MSG.to_string(),
        }
    }

    pub fn new_with_random_padding(padding_size: Range<usize>) -> Self {
        let mut res = Self::new();
        let mut rng = rand::rng();
        let len1 = rng.random_range(padding_size.clone());
        let len2 = rng.random_range(padding_size);
        res.padding_start = generate_random_u8_vec(len1);
        res.padding_end = generate_random_u8_vec(len2);
        res
    }

    pub fn validate(&self) -> bool {
        self.validate_msg.eq(SERVER_VALIDATE_MSG)
    }
    pub fn validate_arc(data: &ArchivedServerHelloStruct) -> bool {
        data.validate_msg.eq(SERVER_VALIDATE_MSG)
    }
}
#[derive(Serialize, Deserialize, Debug, Archive)]
pub struct ClientBeginStruct{
    pub padding_start: Vec<u8>,
    pub s_type: ObSType,
    pub validate_msg: String,
    pub padding_end: Vec<u8>,
}

impl ClientBeginStruct {
    pub fn new() -> Self {
        Self {
            padding_start: vec![],
            padding_end: vec![],
            s_type: ClientBegin,
            validate_msg: CLIENT_BEGIN.to_string(),
        }
    }
    pub fn new_with_random_padding(padding_size: Range<usize>) -> Self {
        let mut res = Self::new();
        let mut rng = rand::rng();
        let len1 = rng.random_range(padding_size.clone());
        let len2 = rng.random_range(padding_size);
        res.padding_start = generate_random_u8_vec(len1);
        res.padding_end = generate_random_u8_vec(len2);
        res
    }
    
    pub fn validate(&self) -> bool {
        self.validate_msg.eq(CLIENT_BEGIN)
    }
    pub fn validate_arc(data: &ArchivedClientBeginStruct) -> bool {
        data.validate_msg.eq(CLIENT_BEGIN)
    }
}
