use nom::Err as NomErr;
use tls_parser::{parse_tls_record_header, TlsRecordHeader};

/// An owned, fully reassembled TLS record.
#[derive(Debug, Clone)]
pub struct TlsRecord {
    pub header: TlsRecordHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsInspectorState {
    /// We haven't established that this is TLS yet.
    Detecting,

    /// TLS has been confirmed for this stream.
    ConfirmedTls,

    /// This stream is not TLS.
    NotTls,
}

pub struct TlsRecordReassembler {
    direction: TlsDirection,

    /// Bytes received but not yet consumed as complete TLS records.
    buf: Vec<u8>,

    /// Header + total record length of the record currently being
    /// assembled.
    pending: Option<(TlsRecordHeader, usize)>,

    state: TlsInspectorState,

    /// True until the first complete TLS record has been processed.
    first_record: bool,
}

impl TlsRecordReassembler {
    pub fn new(direction: TlsDirection) -> Self {
        Self {
            direction,
            buf: Vec::new(),
            pending: None,
            state: TlsInspectorState::Detecting,
            first_record: true,
        }
    }

    pub fn direction(&self) -> TlsDirection {
        self.direction
    }

    pub fn state(&self) -> TlsInspectorState {
        self.state
    }

    pub fn is_tls(&self) -> bool {
        self.state == TlsInspectorState::ConfirmedTls
    }

    pub fn is_not_tls(&self) -> bool {
        self.state == TlsInspectorState::NotTls
    }

    /// Feed bytes from one direction of the TCP stream.
    ///
    /// IMPORTANT:
    ///
    /// The first bytes passed to this inspector must be the first
    /// application bytes of the corresponding TLS direction.
    ///
    /// The inspector NEVER searches for a TLS record at an arbitrary
    /// offset. The first record must start at buf[0].
    pub fn inspect_bytes(&mut self, data: &[u8]) -> Vec<TlsRecord> {
        if self.state == TlsInspectorState::NotTls {
            return Vec::new();
        }

        self.buf.extend_from_slice(data);

        let mut records = Vec::new();

        loop {
            let (header, total_len) = match self.pending.clone() {
                Some(pending) => pending,

                None => {
                    // TLS record header is exactly 5 bytes.
                    if self.buf.len() < 5 {
                        break;
                    }

                    let (_, header) = match parse_tls_record_header(&self.buf) {
                        Ok(result) => result,

                        Err(NomErr::Incomplete(_)) => {
                            // Defensive. We already have >= 5 bytes.
                            break;
                        }

                        Err(_) => {
                            // Because we know that this inspector starts at
                            // the beginning of the stream, there is no reason
                            // to search further into the buffer.
                            self.mark_not_tls();
                            break;
                        }
                    };

                    // Do not trust the advertised length until the header
                    // itself passes sanity checks.
                    if !Self::plausible_record_header(&header) {
                        self.mark_not_tls();
                        break;
                    }

                    let total_len = 5 + header.len as usize;

                    self.pending = Some((header.clone(), total_len));

                    (header, total_len)
                }
            };

            // Header is known, but the complete TLS record hasn't arrived.
            if self.buf.len() < total_len {
                break;
            }

            let payload = self.buf[5..total_len].to_vec();

            // The first complete record is used to validate that this
            // direction actually belongs to a TLS connection.
            if self.first_record {
                if !self.validate_first_record(&header, &payload) {
                    self.mark_not_tls();
                    break;
                }

                self.first_record = false;
                self.state = TlsInspectorState::ConfirmedTls;
            }

            records.push(TlsRecord {
                header,
                payload,
            });

            // Remove exactly one complete TLS record.
            self.buf.drain(0..total_len);
            self.pending = None;

            // If more complete records are already buffered, process them
            // immediately.
        }

        records
    }

    /// Validate a TLS record header without trying to determine whether
    /// the complete stream is TLS.
    fn plausible_record_header(header: &TlsRecordHeader) -> bool {
        // TLS record content types:
        //
        // 20 = ChangeCipherSpec
        // 21 = Alert
        // 22 = Handshake
        // 23 = ApplicationData
        let valid_type = matches!(header.record_type.0, 20 | 21 | 22 | 23);

        // TLS 1.0 .. TLS 1.3 legacy record versions.
        //
        // TLS 1.3 still uses 0x0303 in the record layer.
        let valid_version = matches!(header.version.0, 0x0301..=0x0303);

        // Maximum TLS record payload:
        //
        // TLS 1.2 plaintext: 2^14
        // TLS 1.3 ciphertext: 2^14 + 256
        let valid_length = (header.len as usize) <= 16_640;

        valid_type && valid_version && valid_length
    }

    /// Direction-aware validation of the first record.
    fn validate_first_record(
        &self,
        header: &TlsRecordHeader,
        payload: &[u8],
    ) -> bool {
        match self.direction {
            TlsDirection::ClientToServer => {
                Self::is_client_hello(header, payload)
            }

            TlsDirection::ServerToClient => {
                Self::is_server_hello(header, payload)
            }
        }
    }

    /// Check whether a record begins with a ClientHello handshake.
    ///
    /// TLS Handshake:
    ///
    ///     1 byte  handshake type
    ///     3 bytes handshake length
    ///     N bytes handshake body
    ///
    /// ClientHello = 0x01
    fn is_client_hello(
        header: &TlsRecordHeader,
        payload: &[u8],
    ) -> bool {
        // Handshake record.
        if header.record_type.0 != 22 {
            return false;
        }

        // TLS handshake header.
        if payload.len() < 4 {
            return false;
        }

        // ClientHello.
        if payload[0] != 0x01 {
            return false;
        }

        let handshake_len =
            ((payload[1] as usize) << 16)
                | ((payload[2] as usize) << 8)
                | (payload[3] as usize);

        // The complete handshake message must fit in this record.
        4usize
            .checked_add(handshake_len)
            .is_some_and(|required| required <= payload.len())
    }

    /// Check whether a record begins with a ServerHello handshake.
    ///
    /// ServerHello = 0x02
    fn is_server_hello(
        header: &TlsRecordHeader,
        payload: &[u8],
    ) -> bool {
        // Handshake record.
        if header.record_type.0 != 22 {
            return false;
        }

        // TLS handshake header.
        if payload.len() < 4 {
            return false;
        }

        // ServerHello.
        if payload[0] != 0x02 {
            return false;
        }

        let handshake_len =
            ((payload[1] as usize) << 16)
                | ((payload[2] as usize) << 8)
                | (payload[3] as usize);

        // The complete handshake message must fit in this record.
        4usize
            .checked_add(handshake_len)
            .is_some_and(|required| required <= payload.len())
    }

    fn mark_not_tls(&mut self) {
        self.state = TlsInspectorState::NotTls;
        self.pending = None;
        self.buf.clear();
    }
}