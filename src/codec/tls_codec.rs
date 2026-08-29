use std::io;
use tfserver::async_trait::async_trait;
use tfserver::codec::codec_trait::TfCodec;
use tfserver::structures::transport::Transport;
use tokio_util::bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

pub const TLS_HEADER_LEN: usize = 5;
pub const TLS_MAX_RECORD_LEN: usize = 16 * 1024 + 2048;
#[derive(Clone)]
pub struct TlsCodec;

impl TlsCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for TlsCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Not enough data for the TLS record header.
        if src.len() < TLS_HEADER_LEN {
            return Ok(None);
        }

        // TLS record length is bytes 3..5.
        let payload_len =
            u16::from_be_bytes([src[3], src[4]]) as usize;

        if payload_len > TLS_MAX_RECORD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TLS record too large: {payload_len} bytes"),
            ));
        }

        let record_len = TLS_HEADER_LEN + payload_len;

        // We have the header, but not the complete record yet.
        if src.len() < record_len {
            return Ok(None);
        }

        // Remove the complete TLS record, INCLUDING the header.
        let record = src.split_to(record_len);

        // Convert BytesMut -> Bytes without copying.
        Ok(Some(record))
    }
}

impl Encoder<Bytes> for TlsCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: Bytes,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}


#[async_trait]
impl TfCodec for TlsCodec{
    async fn initial_setup(&mut self, transport: &mut Transport) -> bool {
        true
    }
}