use crate::enums::{ContentType, ProtocolVersion};
use crate::msgs::message::{OutboundChunks, OutboundPlainMessage, PlainMessage};
use crate::Error;
pub(crate) const MAX_FRAGMENT_LEN: usize = 16384;
pub(crate) const PACKET_OVERHEAD: usize = 1 + 2 + 2;
pub(crate) const DTLS_PACKET_OVERHEAD: usize = 1 + 2 + 2;
pub(crate) const MAX_FRAGMENT_SIZE: usize = MAX_FRAGMENT_LEN + PACKET_OVERHEAD;
pub(crate) const DTLS_MAX_FRAGMENT_SIZE: usize = MAX_FRAGMENT_LEN + DTLS_PACKET_OVERHEAD;
use alloc::vec;
use std::{collections::HashMap, vec::Vec};

use crate::{
    msgs::codec::{Codec, Reader},
    HandshakeType, InvalidMessage,
};

pub struct MessageFragmenter {
    max_frag: usize,
}

impl Default for MessageFragmenter {
    fn default() -> Self {
        Self {
            max_frag: MAX_FRAGMENT_LEN,
        }
    }
}

impl MessageFragmenter {
    /// Take `msg` and fragment it into new messages with the same type and version.
    ///
    /// Each returned message size is no more than `max_frag`.
    ///
    /// Return an iterator across those messages.
    ///
    /// Payloads are borrowed from `msg`.
    pub fn fragment_message<'a>(
        &self,
        msg: &'a PlainMessage,
    ) -> impl Iterator<Item = OutboundPlainMessage<'a>> + 'a {
        self.fragment_payload(msg.typ, msg.version, msg.payload.bytes().into())
    }

    /// Take `payload` and fragment it into new messages with given type and version.
    ///
    /// Each returned message size is no more than `max_frag`.
    ///
    /// Return an iterator across those messages.
    ///
    /// Payloads are borrowed from `payload`.
    pub(crate) fn fragment_payload<'a>(
        &self,
        typ: ContentType,
        version: ProtocolVersion,
        payload: OutboundChunks<'a>,
    ) -> impl ExactSizeIterator<Item = OutboundPlainMessage<'a>> {
        Chunker::new(payload, self.max_frag).map(move |payload| OutboundPlainMessage {
            typ,
            version,
            payload,
            dtls_params: None,
        })
    }

    /// Set the maximum fragment size that will be produced.
    ///
    /// This includes overhead. A `max_fragment_size` of 10 will produce TLS fragments
    /// up to 10 bytes long.
    ///
    /// A `max_fragment_size` of `None` sets the highest allowable fragment size.
    ///
    /// Returns BadMaxFragmentSize if the size is smaller than 32 or larger than 16389.
    pub fn set_max_fragment_size(&mut self, max_fragment_size: Option<usize>) -> Result<(), Error> {
        self.max_frag = match max_fragment_size {
            Some(sz @ 32..=MAX_FRAGMENT_SIZE) => sz - PACKET_OVERHEAD,
            None => MAX_FRAGMENT_LEN,
            _ => return Err(Error::BadMaxFragmentSize),
        };
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DtlsFragment {
    pub typ: HandshakeType,
    pub length: u32,
    pub message_seq: u16,
    pub fragment_offset: u32,
    pub fragment_length: u32,
    pub fragment: Vec<u8>,
}

impl Codec<'_> for DtlsFragment {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);

        let len_bytes = self.length.to_be_bytes();
        bytes.extend_from_slice(&len_bytes[1..4]);

        self.message_seq.encode(bytes);

        let offset_bytes = self.fragment_offset.to_be_bytes();
        bytes.extend_from_slice(&offset_bytes[1..4]);

        let frag_len_bytes = self.fragment_length.to_be_bytes();
        bytes.extend_from_slice(&frag_len_bytes[1..4]);

        bytes.extend_from_slice(&self.fragment);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = HandshakeType::read(r)?;

        let length = match r.take(3) {
            Some(&[a, b, c]) => u32::from_be_bytes([0, a, b, c]),
            _ => return Err(InvalidMessage::MissingData("handshake length")),
        };

        let message_seq = u16::read(r)?;

        let fragment_offset = match r.take(3) {
            Some(&[a, b, c]) => u32::from_be_bytes([0, a, b, c]),
            _ => return Err(InvalidMessage::MissingData("fragment offset")),
        };

        let fragment_length = match r.take(3) {
            Some(&[a, b, c]) => u32::from_be_bytes([0, a, b, c]),
            _ => return Err(InvalidMessage::MissingData("fragment length")),
        };

        let fragment = r
            .take(fragment_length as usize)
            .ok_or(InvalidMessage::MissingData("fragment data"))?
            .to_vec();

        Ok(Self {
            typ,
            length,
            message_seq,
            fragment_offset,
            fragment_length,
            fragment,
        })
    }
}

pub(crate) struct DtlsFragmenter {
    max_fragment_size: usize,
}

impl Default for DtlsFragmenter {
    fn default() -> Self {
        Self {
            max_fragment_size: MAX_FRAGMENT_LEN,
        }
    }
}

impl DtlsFragmenter {
    pub(crate) fn fragment_handshake_message(
        &self,
        typ: HandshakeType,
        message_seq: u16,
        payload: &[u8],
    ) -> Vec<DtlsFragment> {
        let total_length = payload.len();

        if total_length <= self.max_fragment_size {
            return vec![DtlsFragment {
                typ,
                length: total_length as u32,
                message_seq,
                fragment_offset: 0,
                fragment_length: total_length as u32,
                fragment: payload.to_vec(),
            }];
        }

        let mut fragments = Vec::new();
        let mut offset = 0;

        while offset < total_length {
            let remaining = total_length - offset;
            let fragment_len = remaining.min(self.max_fragment_size);

            fragments.push(DtlsFragment {
                typ,
                length: total_length as u32,
                message_seq,
                fragment_offset: offset as u32,
                fragment_length: fragment_len as u32,
                fragment: payload[offset..offset + fragment_len].to_vec(),
            });

            offset += fragment_len;
        }

        fragments
    }

    pub(crate) fn fragment_payload<'a>(
        &self,
        typ: ContentType,
        version: ProtocolVersion,
        payload: OutboundChunks<'a>,
    ) -> impl ExactSizeIterator<Item = OutboundPlainMessage<'a>> {
        Chunker::new(payload, self.max_fragment_size).map(move |payload| OutboundPlainMessage {
            typ,
            version,
            payload,
            dtls_params: None,
        })
    }

    pub fn set_max_fragment_size(&mut self, max_fragment_size: Option<usize>) -> Result<(), Error> {
        self.max_fragment_size = match max_fragment_size {
            Some(sz @ 32..=DTLS_MAX_FRAGMENT_SIZE) => sz - DTLS_PACKET_OVERHEAD,
            None => MAX_FRAGMENT_LEN,
            _ => return Err(Error::BadMaxFragmentSize),
        };
        Ok(())
    }
}

pub(crate) struct DtlsReassembler {
    fragments: HashMap<u16, Vec<DtlsFragment>>,
}

impl DtlsReassembler {
    pub(crate) fn new() -> Self {
        Self {
            fragments: HashMap::new(),
        }
    }

    pub(crate) fn add_fragment(
        &mut self,
        fragment: DtlsFragment,
    ) -> Result<Option<Vec<u8>>, InvalidMessage> {
        let seq = fragment.message_seq;
        let total_length = fragment.length as usize;

        if fragment.fragment_offset as usize + fragment.fragment_length as usize > total_length {
            return Err(InvalidMessage::MessageTooLarge);
        }

        self.fragments
            .entry(seq)
            .or_default()
            .push(fragment);

        if let Some(fragments) = self.fragments.get(&seq) {
            if let Some(complete) = Self::try_reassemble(fragments, total_length)? {
                self.fragments.remove(&seq);
                return Ok(Some(complete));
            }
        }

        Ok(None)
    }

    fn try_reassemble(
        fragments: &[DtlsFragment],
        total_length: usize,
    ) -> Result<Option<Vec<u8>>, InvalidMessage> {
        let mut complete = vec![false; total_length];

        for frag in fragments {
            let start = frag.fragment_offset as usize;
            let end = start + frag.fragment_length as usize;

            if end > total_length {
                return Err(InvalidMessage::MessageTooLarge);
            }

            for i in start..end {
                complete[i] = true;
            }
        }

        if !complete.iter().all(|&x| x) {
            return Ok(None);
        }

        let mut message = vec![0u8; total_length];

        for frag in fragments {
            let start = frag.fragment_offset as usize;
            let end = start + frag.fragment.len();
            message[start..end].copy_from_slice(&frag.fragment);
        }

        Ok(Some(message))
    }
}

/// An iterator over borrowed fragments of a payload
struct Chunker<'a> {
    payload: OutboundChunks<'a>,
    limit: usize,
}

impl<'a> Chunker<'a> {
    fn new(payload: OutboundChunks<'a>, limit: usize) -> Self {
        Self { payload, limit }
    }
}

impl<'a> Iterator for Chunker<'a> {
    type Item = OutboundChunks<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.is_empty() {
            return None;
        }

        let (before, after) = self.payload.split_at(self.limit);
        self.payload = after;
        Some(before)
    }
}

impl ExactSizeIterator for Chunker<'_> {
    fn len(&self) -> usize {
        (self.payload.len() + self.limit - 1) / self.limit
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;
    use std::vec;

    use super::{MessageFragmenter, PACKET_OVERHEAD};
    use crate::enums::{ContentType, ProtocolVersion};
    use crate::msgs::base::Payload;
    use crate::msgs::fragmenter::{DtlsFragment, DtlsFragmenter, DtlsReassembler};
    use crate::msgs::message::{OutboundChunks, OutboundPlainMessage, PlainMessage};
    use crate::HandshakeType;

    fn msg_eq(
        m: &OutboundPlainMessage<'_>,
        total_len: usize,
        typ: &ContentType,
        version: &ProtocolVersion,
        bytes: &[u8],
    ) {
        assert_eq!(&m.typ, typ);
        assert_eq!(&m.version, version);
        assert_eq!(m.payload.to_vec(), bytes);

        let buf = m.to_unencrypted_opaque().encode();

        assert_eq!(total_len, buf.len());
    }

    #[test]
    fn smoke() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let data: Vec<u8> = (1..70u8).collect();
        let m = PlainMessage {
            typ,
            version,
            payload: Payload::new(data),
        };

        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment_message(&m)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 3);
        msg_eq(
            &q[0],
            32,
            &typ,
            &version,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27,
            ],
        );
        msg_eq(
            &q[1],
            32,
            &typ,
            &version,
            &[
                28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                49, 50, 51, 52, 53, 54,
            ],
        );
        msg_eq(
            &q[2],
            20,
            &typ,
            &version,
            &[55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69],
        );
    }

    #[test]
    fn non_fragment() {
        let m = PlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
        };

        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment_message(&m)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 1);
        msg_eq(
            &q[0],
            PACKET_OVERHEAD + 8,
            &ContentType::Handshake,
            &ProtocolVersion::TLSv1_2,
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
        );
    }

    #[test]
    fn fragment_multiple_slices() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let payload_owner: Vec<&[u8]> = vec![&[b'a'; 8], &[b'b'; 12], &[b'c'; 32], &[b'd'; 20]];
        let borrowed_payload = OutboundChunks::new(&payload_owner);
        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(37)) // 32 + packet overhead
            .unwrap();

        let fragments = frag
            .fragment_payload(typ, version, borrowed_payload)
            .collect::<Vec<_>>();
        assert_eq!(fragments.len(), 3);
        msg_eq(
            &fragments[0],
            37,
            &typ,
            &version,
            b"aaaaaaaabbbbbbbbbbbbcccccccccccc",
        );
        msg_eq(
            &fragments[1],
            37,
            &typ,
            &version,
            b"ccccccccccccccccccccdddddddddddd",
        );
        msg_eq(&fragments[2], 13, &typ, &version, b"dddddddd");
    }

    #[test]
    fn test_no_fragmentation_needed() {
        let fragmenter = DtlsFragmenter::default();
        let payload = vec![0x42; 100];

        let fragments =
            fragmenter.fragment_handshake_message(HandshakeType::ClientHello, 0, &payload);

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].fragment_offset, 0);
        assert_eq!(fragments[0].fragment_length, 100);
    }

    #[test]
    fn test_fragmentation() {
        let fragmenter = DtlsFragmenter::default();
        let payload = vec![0x42; 150];

        let fragments =
            fragmenter.fragment_handshake_message(HandshakeType::Certificate, 5, &payload);

        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0].fragment_offset, 0);
        assert_eq!(fragments[0].fragment_length, 50);
        assert_eq!(fragments[1].fragment_offset, 50);
        assert_eq!(fragments[1].fragment_length, 50);
        assert_eq!(fragments[2].fragment_offset, 100);
        assert_eq!(fragments[2].fragment_length, 50);

        for frag in &fragments {
            assert_eq!(frag.length, 150);
            assert_eq!(frag.message_seq, 5);
        }
    }

    #[test]
    fn test_reassembly_in_order() {
        let mut reassembler = DtlsReassembler::new();

        let fragments = [
            DtlsFragment {
                typ: HandshakeType::Certificate,
                length: 150,
                message_seq: 0,
                fragment_offset: 0,
                fragment_length: 50,
                fragment: vec![0x41; 50],
            },
            DtlsFragment {
                typ: HandshakeType::Certificate,
                length: 150,
                message_seq: 0,
                fragment_offset: 50,
                fragment_length: 50,
                fragment: vec![0x42; 50],
            },
            DtlsFragment {
                typ: HandshakeType::Certificate,
                length: 150,
                message_seq: 0,
                fragment_offset: 100,
                fragment_length: 50,
                fragment: vec![0x43; 50],
            },
        ];

        assert!(reassembler
            .add_fragment(fragments[0].clone())
            .unwrap()
            .is_none());
        assert!(reassembler
            .add_fragment(fragments[1].clone())
            .unwrap()
            .is_none());

        let complete = reassembler
            .add_fragment(fragments[2].clone())
            .unwrap();
        assert!(complete.is_some());

        let message = complete.unwrap();
        assert_eq!(message.len(), 150);
        assert_eq!(&message[0..50], &vec![0x41; 50][..]);
        assert_eq!(&message[50..100], &vec![0x42; 50][..]);
        assert_eq!(&message[100..150], &vec![0x43; 50][..]);
    }

    #[test]
    fn test_reassembly_out_of_order() {
        let mut reassembler = DtlsReassembler::new();

        let fragments = [
            DtlsFragment {
                typ: HandshakeType::Certificate,
                length: 100,
                message_seq: 0,
                fragment_offset: 50,
                fragment_length: 50,
                fragment: vec![0x42; 50],
            },
            DtlsFragment {
                typ: HandshakeType::Certificate,
                length: 100,
                message_seq: 0,
                fragment_offset: 0,
                fragment_length: 50,
                fragment: vec![0x41; 50],
            },
        ];

        assert!(reassembler
            .add_fragment(fragments[0].clone())
            .unwrap()
            .is_none());

        let complete = reassembler
            .add_fragment(fragments[1].clone())
            .unwrap();
        assert!(complete.is_some());

        let message = complete.unwrap();
        assert_eq!(&message[0..50], &vec![0x41; 50][..]);
        assert_eq!(&message[50..100], &vec![0x42; 50][..]);
    }
}
