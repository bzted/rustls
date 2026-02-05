use crate::{
    crypto::cipher::{MessageDecrypter, MessageEncrypter},
    dtls13::{ack::AckMessage, record_layer::{ConnectionId, DtlsRecordLayer}},
    error::Error,
    record_layer::{PreEncryptAction, RecordLayer},
};
use core::panic;
use std::{boxed::Box, vec::Vec};

use crate::{
    msgs::message::{InboundOpaqueMessage, OutboundPlainMessage},
    record_layer::Decrypted,
};
pub(crate) enum AnyRecordLayer {
    Tls(RecordLayer),
    Dtls(Box<DtlsRecordLayer>),
}

impl AnyRecordLayer {
    pub(crate) fn decrypt_incoming<'a>(
        &mut self,
        record: IncomingRecord<'a>,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        match self {
            Self::Tls(r) => r.decrypt_incoming(record.opaque),
            Self::Dtls(r) => {
                let epoch = record.epoch.expect("Epoch missing");
                let seq = record
                    .seq
                    .expect("Sequence number missing");

                r.as_mut()
                    .decrypt_incoming(record.opaque, epoch, seq, record.cid)
            }
        }
    }

    pub(crate) fn encrypt_fragment(&mut self, msg: OutboundPlainMessage<'_>) -> (Vec<u8>, u64) {
        match self {
            Self::Tls(r) => (r.encrypt_outgoing(msg).encode(), 0),
            Self::Dtls(r) => r.as_mut().write_dtls_record(msg),
        }
    }

    pub(crate) fn encoded_len(&self, msg: &OutboundPlainMessage<'_>) -> usize {
        match self {
            Self::Tls(r) => msg.encoded_len(r),
            Self::Dtls(r) => msg.dtls_encoded_len(r.as_ref()),
        }
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        match self {
            Self::Tls(r) => r.is_encrypting(),
            Self::Dtls(r) => r.as_ref().is_encrypting(),
        }
    }

    pub(crate) fn pre_encrypt_action(&mut self, add: u64) -> PreEncryptAction {
        match self {
            Self::Tls(r) => r.pre_encrypt_action(add),
            Self::Dtls(r) => r.as_mut().pre_encrypt_action(add),
        }
    }

    pub(crate) fn next_pre_encrypt_action(&mut self) -> PreEncryptAction {
        match self {
            Self::Tls(r) => r.next_pre_encrypt_action(),
            Self::Dtls(r) => r.as_mut().next_pre_encrypt_action(),
        }
    }

    pub(crate) fn prepare_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        match self {
            Self::Tls(r) => r.prepare_message_encrypter(cipher, max_messages),
            Self::Dtls(r) => r
                .as_mut()
                .prepare_message_encrypter(cipher, max_messages),
        }
    }

    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        match self {
            Self::Tls(r) => r.prepare_message_decrypter(cipher),
            Self::Dtls(r) => r
                .as_mut()
                .prepare_message_decrypter(cipher),
        }
    }

    pub(crate) fn set_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        match self {
            Self::Tls(r) => r.set_message_encrypter(cipher, max_messages),
            Self::Dtls(r) => r
                .as_mut()
                .set_message_encrypter(cipher, max_messages),
        }
    }

    pub(crate) fn set_message_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        max_length: usize,
    ) {
        match self {
            Self::Tls(r) => r.set_message_decrypter_with_trial_decryption(cipher, max_length),
            Self::Dtls(r) => r
                .as_mut()
                .set_message_decrypter_with_trial_decryption(cipher, max_length),
        }
    }

    pub(crate) fn set_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        match self {
            Self::Tls(r) => r.set_message_decrypter(cipher),
            Self::Dtls(r) => r.as_mut().set_message_decrypter(cipher),
        }
    }

    pub(crate) fn has_decrypted(&self) -> bool {
        match self {
            Self::Tls(r) => r.has_decrypted(),
            Self::Dtls(r) => r.as_ref().has_decrypted(),
        }
    }

    pub(crate) fn finish_trial_decryption(&mut self) {
        match self {
            Self::Tls(r) => r.finish_trial_decryption(),
            Self::Dtls(r) => r.as_mut().finish_trial_decryption(),
        }
    }

    pub(crate) fn write_seq(&self) -> u64 {
        match self {
            Self::Tls(r) => r.write_seq(),
            Self::Dtls(r) => r.as_ref().write_seq(),
        }
    }

    pub(crate) fn read_seq(&self) -> u64 {
        match self {
            Self::Tls(r) => r.read_seq(),
            Self::Dtls(r) => r.as_ref().read_seq(),
        }
    }

    pub(crate) fn start_encrypting(&mut self) {
        match self {
            Self::Tls(r) => r.start_encrypting(),
            Self::Dtls(r) => r.as_mut().start_encrypting(),
        }
    }

    pub(crate) fn start_decrypting(&mut self) {
        match self {
            Self::Tls(r) => r.start_decrypting(),
            Self::Dtls(r) => r.as_mut().start_decrypting(),
        }
    }

    pub(crate) fn read_cid_len(&self) -> usize {
        match self {
            Self::Tls(_) => panic!(),
            Self::Dtls(r) => r.as_ref().read_cid_length(),
        }
    }

    pub(crate) fn write_epoch(&self) -> u16 {
        match self {
            Self::Tls(_) => panic!(),
            Self::Dtls(r) => r.as_ref().write_epoch(),
        }
    }

    pub(crate) fn read_epoch(&self) -> u16 {
        match self {
            Self::Tls(_) => panic!(),
            Self::Dtls(r) => r.as_ref().read_epoch(),
        }
    }

    pub(crate) fn write_dtls_plain_record(
        &mut self,
        msg: OutboundPlainMessage<'_>,
    ) -> (Vec<u8>, u64) {
        match self {
            Self::Tls(_) => panic!(),
            Self::Dtls(r) => r.as_mut().write_dtls_plain_record(msg),
        }
    }

    pub(crate) fn start_flight(&mut self) {
        match self {
            Self::Tls(_) => panic!(),
            Self::Dtls(r) => r.as_mut().start_flight(),
        }
    }

    pub(crate) fn add_record(&mut self, datagrams: Vec<Vec<u8>>, record_nums: Vec<u64>) {
        match self {
            Self::Tls(_) => panic!(),
            Self::Dtls(r) => r
                .as_mut()
                .add_record(datagrams, record_nums),
        }
    }

    pub(crate) fn mark_sent(&mut self) {
        match self {
            Self::Tls(_) => panic!(),
            Self::Dtls(r) => r.as_mut().mark_sent(),
        }
    }

    pub(crate) fn generate_ack_message(&mut self) -> Option<AckMessage> {
        match self {
            Self::Tls(_) => None,
            Self::Dtls(r) => r.as_mut().generate_ack_message(),
        }
    }

    pub(crate) fn advance_write_epoch(&mut self) {
        match self {
            Self::Tls(_) => panic!(),
            Self::Dtls(r) => r.as_mut().advance_write_epoch(),
        }
    }

    pub(crate) fn advance_read_epoch(&mut self) {
        match self {
            Self::Tls(_) => panic!(),
            Self::Dtls(r) => r.as_mut().advance_read_epoch(),
        }
    }

    pub(crate) fn retransmit(&mut self) -> Option<&[Vec<u8>]> {
        match self {
            Self::Tls(_) => None,
            Self::Dtls(r) => r.as_mut().retransmit(),
        }
    }

    pub(crate) fn set_write_cid(&mut self, cid: ConnectionId) {
        match self {
            Self::Tls(_) => (),
            Self::Dtls(r) => r.as_mut().set_write_cid(cid),
        }
    }

    pub(crate) fn set_read_cid(&mut self, cid: ConnectionId) {
        match self {
            Self::Tls(_) => (),
            Self::Dtls(r) => r.as_mut().set_read_cid(cid),
        }
    }

    pub(crate) fn clear_write_cid(&mut self) {
        match self {
            Self::Tls(_) => (),
            Self::Dtls(r) => r.as_mut().clear_write_cid(),
        }
    }

    pub(crate) fn clear_read_cid(&mut self) {
        match self {
            Self::Tls(_) => (),
            Self::Dtls(r) => r.as_mut().clear_read_cid(),
        }
    }
}
pub(crate) struct IncomingRecord<'a> {
    pub opaque: InboundOpaqueMessage<'a>,
    pub epoch: Option<u16>,
    pub seq: Option<u64>,
    pub cid: Option<&'a [u8]>,
}
