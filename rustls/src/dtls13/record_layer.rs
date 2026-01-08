use alloc::vec;
use core::ops::Range;
use std::boxed::Box;
use std::vec::Vec;

use crate::dtls13::ack::AckMessage;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::fragmenter::{DtlsFragment, DtlsReassembler};
use log::debug;
use log::trace;

use crate::crypto::cipher::{MessageDecrypter, MessageEncrypter};
use crate::dtls13::flight::FlightTracker;
use crate::error::Error;
use crate::msgs::message::{InboundPlainMessage, OutboundOpaqueMessage, OutboundPlainMessage};
use crate::record_layer::PreEncryptAction;
use crate::{
    dtls13::anti_replay::AntiReplayWindow,
    msgs::message::InboundOpaqueMessage,
    record_layer::{Decrypted, RecordLayer},
};
use crate::{ContentType, HandshakeType, InvalidMessage, PeerMisbehaved, ProtocolVersion};

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
        }
    }

    /// Decrypt a DTLS message with epoch verification and anti-replay protection.
    /// 'encr' is a decoded message allegedly received from the peer.
    /// 'epoch' and 'seq' should be extracted from the DTLS record header.
    /// After verifying them, we delegate to the TLS record layer.
    pub(crate) fn decrypt_incoming<'a>(
        &mut self,
        encr: InboundOpaqueMessage<'a>,
        epoch: u16,
        seq: u64,
        cid: Option<&[u8]>,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        if epoch != self.read_epoch {
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

        let dec = self.record.decrypt_incoming(encr)?;

        if let Some(ref d) = dec {
            if d.plaintext.typ == ContentType::Ack {
                self.flight_tracker
                    .process_ack_payload(d.plaintext.payload)?;
                return Ok(None);
            }
        }

        if dec.is_some() && !self.replay_window.check(seq) {
            debug!(
                "Dropping replayed or out of window message with seq: {} ",
                seq
            );
            return Ok(None);
        }

        if let Some(ref d) = dec {
            self.flight_tracker
                .record_received(epoch, seq);
        }

        Ok(dec)
    }

    /// Encrypt a DTLS message, returning the encrypted message along with
    /// the current epoch and sequence number to include in the header
    /// Delegate to TLS record layer for actual encryption
    pub(crate) fn encrypt_outgoing(
        &mut self,
        plain: OutboundPlainMessage<'_>,
    ) -> (OutboundOpaqueMessage, u16, u64, Option<&[u8]>) {
        let epoch = self.write_epoch;
        let seq = self.write_seq;
        self.write_seq = self.write_seq.wrapping_add(1);
        let cid = self
            .write_cid
            .as_ref()
            .map(|c| c.cid.as_slice());

        let encrypted = self.record.encrypt_outgoing(plain);

        (encrypted, epoch, seq, cid)
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

    pub(crate) fn has_read_cid(&self) -> bool {
        self.read_cid.is_some()
    }

    pub(crate) fn has_write_cid(&self) -> bool {
        self.write_cid.is_some()
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

    pub(crate) fn inner(&self) -> &RecordLayer {
        &self.record
    }

    pub(crate) fn inner_mut(&mut self) -> &mut RecordLayer {
        &mut self.record
    }

    pub(crate) fn write_dtls_record(&mut self, plain: OutboundPlainMessage<'_>) -> (Vec<u8>, u64) {
        let (encrypted, epoch, seq, cid) = self.encrypt_outgoing(plain);

        let mut output = Vec::new();

        encrypted.typ.encode(&mut output);

        ProtocolVersion::DTLSv1_2.encode(&mut output);

        epoch.encode(&mut output);

        let seq_bytes = seq.to_be_bytes();
        output.extend_from_slice(&seq_bytes[2..8]);

        if let Some(cid_bytes) = cid {
            output.extend_from_slice(cid_bytes);
        }

        let payload = encrypted.payload.as_ref();
        (payload.len() as u16).encode(&mut output);

        output.extend_from_slice(payload);
        debug!(
            "Writing encrypted message. Epoch: {:?}, seq: {:?}",
            epoch, seq
        );

        (output, seq)
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
        let cid = self
            .write_cid
            .as_ref()
            .map(|c| c.cid.as_slice());

        let payload = &plain.payload.to_vec();

        let mut out = Vec::new();
        plain.typ.encode(&mut out);
        ProtocolVersion::DTLSv1_2.encode(&mut out);
        epoch.encode(&mut out);

        let seq_bytes = seq.to_be_bytes();
        out.extend_from_slice(&seq_bytes[2..]);

        if let Some(c) = cid {
            out.extend_from_slice(c);
        }

        (payload.len() as u16).encode(&mut out);
        out.extend_from_slice(payload);

        (out, seq)
    }

    pub(crate) fn generate_ack_message(&self) -> AckMessage {
        self.flight_tracker.generate_ack()
    }

    pub(crate) fn poll_retransmit(&mut self) -> Option<&[Vec<u8>]> {
        self.flight_tracker.poll_timeout()
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
