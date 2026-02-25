use std::boxed::Box;
use std::vec::Vec;

use crate::dtls13::ack::AckMessage;
use crate::dtls13::crypto::header::HeaderEncrypter;
use crate::msgs::codec::{Codec, Reader};
use log::debug;

use crate::crypto::cipher::{MessageDecrypter, MessageEncrypter};
use crate::dtls13::flight::FlightTracker;
use crate::error::Error;
use crate::msgs::message::{ OutboundOpaqueMessage, OutboundPlainMessage};
use crate::record_layer::PreEncryptAction;
use crate::{
    dtls13::anti_replay::AntiReplayWindow,
    msgs::message::InboundOpaqueMessage,
    record_layer::{Decrypted, RecordLayer},
};
use crate::{ContentType, InvalidMessage, ProtocolVersion};

pub(crate) struct DtlsRecordLayer {
    record: RecordLayer,
    write_seq: u64,
    write_epoch: u16,
    read_epoch: u16,
    replay_window: AntiReplayWindow,
    write_cid: Option<ConnectionId>,
    read_cid: Option<ConnectionId>,
    flight_tracker: FlightTracker,
    plain_record_seq: u64,
    write_header_protection: Option<Box<dyn HeaderEncrypter>>,
    read_header_protection: Option<Box<dyn HeaderEncrypter>>,
}

impl DtlsRecordLayer {
    pub(crate) fn new() -> Self {
        Self {
            record: RecordLayer::new(),
            write_seq: 0,
            write_epoch: 0,
            read_epoch: 0,
            replay_window: AntiReplayWindow::new(),
            write_cid: None,
            read_cid: None,
            flight_tracker: FlightTracker::new(),
            plain_record_seq: 0,
            write_header_protection: None,
            read_header_protection: None,
        }
    }

    /// Decrypt a DTLS message with epoch verification and anti-replay protection.
    /// 'encr' is a decoded message allegedly received from the peer.
    /// 'epoch' and 'seq' should be extracted from the DTLS record header.
    pub(crate) fn decrypt_incoming<'a>(
        &mut self,
        encr: InboundOpaqueMessage<'a>,
        epoch: u16,
        masked_seq: u64,
        cid: Option<&[u8]>,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        if (self.read_epoch & 0x0003) != (epoch & 0x0003) {
            debug!(
                "Dropping message with wrong epoch: expected {}, got {}",
                self.read_epoch, epoch
            );
            return Ok(None);
        }

        if let Some(expected_cid) = &self.read_cid {
            match cid {
                Some(received_cid) if received_cid == expected_cid.cid.as_slice() => {}
                Some(received_cid) => {
                    debug!(
                        "Dropping message with wrong CID: expected {:?}, got {:?}",
                        expected_cid.cid.as_slice(),
                        received_cid
                    );
                    return Ok(None);
                }
                None => {
                    debug!("Dropping message with unexpected CID");
                    return Ok(None);
                }
            }
        } else if cid.is_some() {
            debug!("Dropping message with unexpected CID");
            return Ok(None);
        }

        let mut clean_seq = masked_seq as u16;

        let is_16bit_seq = if let Some(h) = &encr.dtls_aad {
            (h[0] & 0x08) != 0
        } else {
            true
        };

        let seq_len = if is_16bit_seq { 2 } else { 1 };

        if let Some(protector) = &self.read_header_protection {
            if encr.payload.len() < 16 {
                return Err(Error::InvalidMessage(InvalidMessage::MessageTooShort));
            }

            let sample = &encr.payload[0..16];
            let mask = protector.compute_mask(sample);

            if is_16bit_seq {
                let mut seq_bytes = (masked_seq as u16).to_be_bytes();
                seq_bytes[0] ^= mask[0];
                seq_bytes[1] ^= mask[1];
                clean_seq = u16::from_be_bytes(seq_bytes);
            } else {
                let mut seq_byte = masked_seq as u8;
                seq_byte ^= mask[0];
                clean_seq = seq_byte as u16;
            }
        }

        let seq = self.reconstruct_seq_num(clean_seq as u64, seq_len);

        debug!("Attempting to decrypt record with seq: {:?}", seq);

        let mut encr_with_aad = encr;
        if let Some(h) = &mut encr_with_aad.dtls_aad {
            let seq_offset = 1 + cid.map_or(0, |c| c.len());
            
            if is_16bit_seq {
                let seq_bytes = (clean_seq as u16).to_be_bytes();
                h[seq_offset] = seq_bytes[0];
                h[seq_offset + 1] = seq_bytes[1];
            } else {
                h[seq_offset] = clean_seq as u8;
            }
        }
    
        let dec = self.record.decrypt_incoming_with_seq(encr_with_aad, seq)?;

        if let Some(ref d) = dec {
            if d.plaintext.typ == ContentType::Ack {
                self.flight_tracker
                    .process_ack_payload(d.plaintext.payload)?;
                return Ok(dec);
            }
        }

        if dec.is_some() && !self.replay_window.check(seq) {
            debug!(
                "Dropping replayed or out of window message with seq: {} ",
                seq
            );
            return Ok(None);
        }

        if let Some(ref _d) = dec {
            self.flight_tracker
                .record_received(self.read_epoch, seq);
        }

        Ok(dec)
    }

    /// Encrypt a DTLS message, returning the encrypted message along with
    /// the current epoch and sequence number to include in the header
    /// Delegate to TLS record layer for actual encryption
    pub(crate) fn encrypt_outgoing(
        &mut self,
        mut plain: OutboundPlainMessage<'_>,
    ) -> (OutboundOpaqueMessage, u16, u64, Option<&[u8]>) {
        let epoch = self.write_epoch;
        let seq = self.write_seq;
        self.write_seq = self.write_seq.wrapping_add(1);
        let cid = self.write_cid.as_ref().map(|c| c.cid.clone());
        let cid_ref = self.write_cid.as_ref().map(|c| c.cid.as_slice());

        plain.dtls_params = Some((epoch, cid, true));
        let encrypted = self.record.encrypt_outgoing(plain);

        (encrypted, epoch, seq, cid_ref)
    }

    pub(crate) fn write_epoch(&self) -> u16 {
        self.write_epoch
    }

    pub(crate) fn read_epoch(&self) -> u16 {
        self.read_epoch
    }

    pub(crate) fn advance_write_epoch(&mut self) {
        self.write_epoch = self
            .write_epoch
            .checked_add(1)
            .expect("Epoch overflow");
        self.write_seq = 0;
    }

    pub(crate) fn advance_read_epoch(&mut self) {
        self.read_epoch = self
            .read_epoch
            .checked_add(1)
            .expect("Epoch overflow");
        self.replay_window.reset();
    }

    pub(crate) fn read_cid_length(&self) -> usize {
        self.read_cid
            .as_ref()
            .map(|cid| cid.cid.len())
            .unwrap_or(0)
    }

    pub(crate) fn write_cid_length(&self) -> usize {
        self.write_cid
            .as_ref()
            .map(|cid| cid.cid.len())
            .unwrap_or(0)
    }

    pub(crate) fn set_write_cid(&mut self, cid: ConnectionId) {
        self.write_cid = Some(cid);
    }

    pub(crate) fn set_read_cid(&mut self, cid: ConnectionId) {
        self.read_cid = Some(cid);
    }

    pub(crate) fn clear_write_cid(&mut self) {
        self.write_cid = None;
    }

    pub(crate) fn clear_read_cid(&mut self) {
        self.read_cid = None;
    }

    pub(crate) fn prepare_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        self.record
            .prepare_message_encrypter(cipher, max_messages);
    }

    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.record
            .prepare_message_decrypter(cipher);
    }

    pub(crate) fn start_encrypting(&mut self) {
        self.record.start_encrypting();
    }

    pub(crate) fn start_decrypting(&mut self) {
        self.record.start_decrypting();
    }

    pub(crate) fn set_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        self.record
            .set_message_encrypter(cipher, max_messages);
    }

    pub(crate) fn set_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.record
            .set_message_decrypter(cipher);
    }

    pub(crate) fn set_message_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        max_length: usize,
    ) {
        self.record
            .set_message_decrypter_with_trial_decryption(cipher, max_length);
    }

    pub(crate) fn finish_trial_decryption(&mut self) {
        self.record.finish_trial_decryption();
    }

    pub(crate) fn next_pre_encrypt_action(&mut self) -> PreEncryptAction {
        self.record.next_pre_encrypt_action()
    }

    pub(crate) fn pre_encrypt_action(&mut self, add: u64) -> PreEncryptAction {
        self.record.pre_encrypt_action(add)
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.record.is_encrypting()
    }

    pub(crate) fn has_decrypted(&self) -> bool {
        self.record.has_decrypted()
    }

    pub(crate) fn write_seq(&self) -> u64 {
        self.record.write_seq()
    }

    pub(crate) fn read_seq(&self) -> u64 {
        self.record.read_seq()
    }

    pub(crate) fn encrypted_len(&self, payload_len: usize) -> usize {
        self.record.encrypted_len(payload_len)
    }

    pub(crate) fn write_dtls_record(&mut self, plain: OutboundPlainMessage<'_>) -> (Vec<u8>, u64) {
        let (encrypted, epoch, seq, cid) = self.encrypt_outgoing(plain);
        let payload = encrypted.payload.as_ref();

        debug_assert!(payload.len() >= 16, "DTLS 1.3 payload too short for header protection");

        let c = cid.is_some();
        let s = true; // 16-bit seq
        let l = true; // length present
        let ee = (epoch & 0x0003) as u8;

        let first = 0b0010_0000
            | ((c as u8) << 4)
            | ((s as u8) << 3)
            | ((l as u8) << 2)
            | ee;

        let mut out = Vec::with_capacity(
            1
            + cid.map(|c| c.len()).unwrap_or(0)
            + 2  // seq16
            + 2  // length
            + payload.len(),
        );

        out.push(first);

        if let Some(cid) = cid {
            out.extend_from_slice(cid);
        }

        let mut seq_bytes = (seq as u16).to_be_bytes();

        if let Some(protector) = &self.write_header_protection {
            let sample = &payload[0..16];
            let mask = protector.compute_mask(sample);

            seq_bytes[0] ^= mask[0];
            seq_bytes[1] ^= mask[1];
        }

        out.extend_from_slice(&seq_bytes);

        let len_u16 = payload.len() as u16;
        out.extend_from_slice(&len_u16.to_be_bytes());

        out.extend_from_slice(payload);

        debug!(
            "Writing encrypted message. Epoch: {:?}, seq: {:?}",
            epoch, seq
        );

        (out, seq)
    }

    pub(crate) fn write_dtls_plain_record(
        &mut self,
        plain: OutboundPlainMessage<'_>,
    ) -> (Vec<u8>, u64) {
        debug!("Writing plain message");
        let epoch = self.write_epoch;
        debug_assert_eq!(epoch, 0);

        let seq = self.plain_record_seq;
        self.plain_record_seq = self.plain_record_seq.wrapping_add(1);

        let payload = &plain.payload.to_vec();

        let mut out = Vec::new();
        plain.typ.encode(&mut out);
        ProtocolVersion::DTLSv1_2.encode(&mut out);
        epoch.encode(&mut out);

        let seq_bytes = seq.to_be_bytes();
        out.extend_from_slice(&seq_bytes[2..]);

        (payload.len() as u16).encode(&mut out);
        out.extend_from_slice(payload);

        (out, seq)
    }

    pub(crate) fn generate_ack_message(&mut self) -> AckMessage {
        self.flight_tracker.generate_ack()
    }

    pub(crate) fn retransmit_after_timeout(&mut self) -> Option<&[Vec<u8>]> {
        self.flight_tracker.timeout()
    }

    pub(crate) fn retransmit_after_ack(&mut self) -> Option<&[Vec<u8>]> {
        self.flight_tracker.pending_datagrams()
    }

    pub(crate) fn start_flight(&mut self) {
        self.flight_tracker
            .start_flight(self.write_epoch);
    }

    pub(crate) fn add_record(&mut self, datagrams: Vec<Vec<u8>>, record_nums: Vec<u64>) {
        self.flight_tracker
            .add_record(datagrams, record_nums);
    }

    pub(crate) fn mark_sent(&mut self) {
        self.flight_tracker.mark_sent();
    }

    pub(crate) fn set_header_protection(&mut self, protector: Option<Box<dyn HeaderEncrypter>>) {
        self.write_header_protection = protector;
    }

    pub(crate) fn set_read_header_protection(&mut self, protector: Option<Box<dyn HeaderEncrypter>>) {
        self.read_header_protection = protector;
    }

    fn reconstruct_seq_num(&self, wire_seq: u64, wire_seq_len: usize) -> u64 {
        let mask = (1u64 << (wire_seq_len * 8)) - 1;
        let ref_seq = self.replay_window.get_last_seq();
        let ref_high = ref_seq & !mask;
        let candidate = ref_high | wire_seq;

        let epoch_delta = 1u64 << (wire_seq_len * 8);
        let half_epoch = epoch_delta / 2;

        if candidate <= ref_seq {
            if (ref_seq - candidate) > half_epoch {
                return candidate + epoch_delta;
            }
        } else {
            if (candidate - ref_seq) > half_epoch && ref_high > 0 {
                return candidate - epoch_delta;
            }
        }
        candidate
    }
}

impl Default for DtlsRecordLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionId {
    cid: Vec<u8>,
}

impl ConnectionId {
    pub fn new(cid: Vec<u8>) -> Result<Self, Error> {
        if cid.len() > 255 {
            return Err(Error::General(
                "Connection ID length must not exceed 255 bytes".into(),
            ));
        }
        Ok(Self { cid })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.cid
    }
}

impl From<&ConnectionId> for ConnectionId {
    fn from(cid: &ConnectionId) -> Self {
        ConnectionId { cid: cid.cid.clone() }
    }
}

impl Codec<'_> for ConnectionId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.cid.len() as u8);
        bytes.extend_from_slice(&self.cid);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let len = u8::read(r)? as usize;
        let cid = r
            .take(len)
            .ok_or(InvalidMessage::MessageTooShort)?
            .to_vec();

        Ok(Self { cid })
    }
}
