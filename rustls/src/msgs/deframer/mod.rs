use core::mem;

use log::debug;

use crate::error::{Error, InvalidMessage};
use crate::msgs::codec::Reader;
use crate::msgs::message::{
    DTLS_HEADER_SIZE, HEADER_SIZE, InboundOpaqueMessage, MessageError, read_dtls_plaintext_header, read_dtls13_unified_header, read_opaque_message_header
};
use crate::record_common::IncomingRecord;
use crate::ProtocolVersion;

pub(crate) mod buffers;
pub(crate) mod handshake;

/// A deframer of TLS wire messages.
///
/// Returns `Some(Ok(_))` containing each `InboundOpaqueMessage` deframed
/// from the buffer.
///
/// Returns `None` if no further messages can be deframed from the
/// buffer.  More data is required for further progress.
///
/// Returns `Some(Err(_))` if the peer is not talking TLS, but some
/// other protocol.  The caller should abort the connection, because
/// the deframer cannot recover.
///
/// Call `bytes_consumed()` to learn how many bytes the iterator has
/// processed from the front of the original buffer.  This is only updated
/// when a message is successfully deframed (ie. `Some(Ok(_))` is returned).
pub(crate) struct DeframerIter<'a> {
    buf: &'a mut [u8],
    consumed: usize,
    cid_len: usize,
}

impl<'a> DeframerIter<'a> {
    /// Make a new `DeframerIter`
    pub(crate) fn new(buf: &'a mut [u8], cid_len: usize) -> Self {
        Self {
            buf,
            consumed: 0,
            cid_len,
        }
    }

    /// How many bytes were processed successfully from the front
    /// of the buffer passed to `new()`?
    pub(crate) fn bytes_consumed(&self) -> usize {
        self.consumed
    }

    fn process_dtls13_ciphertext(&mut self) -> Option<Result<IncomingRecord<'a>, Error>> {

        let (has_cid, ee, seq, len, header_len, cid_range) = match read_dtls13_unified_header(self.buf, self.cid_len) {
            Ok(v) => v,
            Err(err) => {
                let err = match err {
                    MessageError::TooShortForHeader | MessageError::TooShortForLength => return None,
                    MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                    MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                    MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                    MessageError::UnknownProtocolVersion => InvalidMessage::UnknownProtocolVersion,
                };
                return Some(Err(err.into()));
            }
        };

        let end = header_len + len;
        self.buf.get(header_len..end)?; 

        let (consumed, remainder) = mem::take(&mut self.buf).split_at_mut(end);
        self.buf = remainder;
        self.consumed += end;

        let (header, body) = consumed.split_at_mut(header_len);

        let cid_slice = if has_cid {
            cid_range.map(|(s, e)| &header[s..e])
        } else {
            None
        };

        let opaque = InboundOpaqueMessage::new_with_aad(crate::ContentType::ApplicationData, ProtocolVersion::DTLSv1_2, body, header.to_vec());

        Some(Ok(IncomingRecord {
            opaque,
            epoch: Some(ee),   
            seq: Some(seq),     
            cid: cid_slice,
        }))
    }


    fn process_dtls_plaintext(&mut self) -> Option<Result<IncomingRecord<'a>, Error>> {
        let (typ, version, epoch, seq, len) = {
            let mut reader = Reader::init(self.buf);
            match read_dtls_plaintext_header(&mut reader) {
                Ok(h) => h,
                Err(err) => {
                    let err = match err {
                        MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                            return None;
                        }
                        MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                        MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                        MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                        MessageError::UnknownProtocolVersion => {
                            InvalidMessage::UnknownProtocolVersion
                        }
                    };
                    return Some(Err(err.into()));
                }
            }
        };

        let header_len = DTLS_HEADER_SIZE + self.cid_len;
        let end = header_len + len as usize;
        self.buf.get(header_len..end)?;

        let (consumed, remainder) = mem::take(&mut self.buf).split_at_mut(end);
        self.buf = remainder;
        self.consumed += end;

        let (_header, body) = consumed.split_at_mut(header_len);

        let opaque = InboundOpaqueMessage::new(typ, version, body);
        Some(Ok(IncomingRecord {
            opaque,
            epoch: Some(epoch),
            seq: Some(seq),
            cid: None,
        }))
    }
}

impl<'a> Iterator for DeframerIter<'a> {
    type Item = Result<IncomingRecord<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let first = *self.buf.get(0)?;

        if (first & 0b1110_0000) == 0b0010_0000 {
            return self.process_dtls13_ciphertext();
        }

        let mut reader = Reader::init(self.buf);
        
        let (typ, version, len) = match read_opaque_message_header(&mut reader) {
            Ok(header) => header,
            Err(err) => {
                let err = match err {
                    MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                        return None;
                    }
                    MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                    MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                    MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                    MessageError::UnknownProtocolVersion => InvalidMessage::UnknownProtocolVersion,
                };
                return Some(Err(err.into()));
            }
        };

        if version == ProtocolVersion::DTLSv1_2 || version == ProtocolVersion::DTLSv1_0 {
            return self.process_dtls_plaintext();
        };

        let end = HEADER_SIZE + len as usize;
        self.buf.get(HEADER_SIZE..end)?;

        // we now have a TLS header and body on the front of `self.buf`.  remove
        // it from the front.
        let (consumed, remainder) = mem::take(&mut self.buf).split_at_mut(end);
        self.buf = remainder;
        self.consumed += end;

        let opaque = InboundOpaqueMessage::new(typ, version, &mut consumed[HEADER_SIZE..]);
        Some(Ok(IncomingRecord {
            opaque,
            epoch: None,
            seq: None,
            cid: None,
        }))
    }
}

pub fn fuzz_deframer(data: &[u8], cid_len: usize) {
    let mut buf = data.to_vec();
    let mut iter = DeframerIter::new(&mut buf, cid_len);

    for message in iter.by_ref() {
        if message.is_err() {
            break;
        }
    }

    assert!(iter.bytes_consumed() <= buf.len());
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use std::prelude::v1::*;

    use super::*;
    use crate::ContentType;

    #[test]
    fn iterator_empty_before_header_received() {
        assert!(DeframerIter::new(&mut [], 0)
            .next()
            .is_none());
        assert!(DeframerIter::new(&mut [0x16], 0)
            .next()
            .is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03], 0)
            .next()
            .is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03, 0x03], 0)
            .next()
            .is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03, 0x03, 0x00], 0)
            .next()
            .is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03, 0x03, 0x00, 0x01], 0)
            .next()
            .is_none());
    }

    #[test]
    fn iterate_one_message() {
        let mut buffer = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
        let mut iter = DeframerIter::new(&mut buffer, 0);
        assert_eq!(
            iter.next().unwrap().unwrap().opaque.typ,
            ContentType::ApplicationData
        );
        assert_eq!(iter.bytes_consumed(), 6);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterate_two_messages() {
        let mut buffer = [
            0x16, 0x03, 0x03, 0x00, 0x01, 0x00, 0x17, 0x03, 0x03, 0x00, 0x01, 0x00,
        ];
        let mut iter = DeframerIter::new(&mut buffer, 0);
        assert_eq!(
            iter.next().unwrap().unwrap().opaque.typ,
            ContentType::Handshake
        );
        assert_eq!(iter.bytes_consumed(), 6);
        assert_eq!(
            iter.next().unwrap().unwrap().opaque.typ,
            ContentType::ApplicationData
        );
        assert_eq!(iter.bytes_consumed(), 12);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_invalid_protocol_version_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-version.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer, 0);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(
                InvalidMessage::UnknownProtocolVersion
            ))
        );
    }

    #[test]
    fn iterator_invalid_content_type_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-contenttype.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer, 0);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidContentType))
        );
    }

    #[test]
    fn iterator_excess_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-length.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer, 0);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::MessageTooLarge))
        );
    }

    #[test]
    fn iterator_zero_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-empty.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer, 0);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload))
        );
    }

    #[test]
    fn iterator_over_many_messages() {
        let client_hello = include_bytes!("../../testdata/deframer-test.1.bin");
        let mut buffer = Vec::with_capacity(3 * client_hello.len());
        buffer.extend(client_hello);
        buffer.extend(client_hello);
        buffer.extend(client_hello);
        let mut iter = DeframerIter::new(&mut buffer, 0);
        let mut count = 0;

        for message in iter.by_ref() {
            let message = message.unwrap();
            assert_eq!(ContentType::Handshake, message.opaque.typ);
            count += 1;
        }

        assert_eq!(count, 3);
        assert_eq!(client_hello.len() * 3, iter.bytes_consumed());
    }

    #[test]
    fn exercise_fuzz_deframer() {
        fuzz_deframer(&[0xff, 0xff, 0xff, 0xff, 0xff], 0);
        for prefix in 0..7 {
            fuzz_deframer(&[0x16, 0x03, 0x03, 0x00, 0x01, 0xff][..prefix], 0);
        }
    }
}
