use log::debug;

use crate::error::Error;
use crate::msgs::codec::{Codec, ListLength, Reader, TlsListElement};
use crate::InvalidMessage;
use std::collections::HashSet;
use std::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RecordNumber {
    pub epoch: u64,
    pub seq: u64,
}

impl TlsListElement for RecordNumber {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl Codec<'_> for RecordNumber {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.epoch.encode(bytes);
        self.seq.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            epoch: u64::read(r)?,
            seq: u64::read(r)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct AckMessage {
    pub record_numbers: Vec<RecordNumber>,
}

impl Codec<'_> for AckMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.record_numbers.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            record_numbers: Vec::read(r)?,
        })
    }
}

impl AckMessage {
    pub(crate) fn new() -> Self {
        Self {
            record_numbers: Vec::new(),
        }
    }

    pub(crate) fn add_record(&mut self, epoch: u16, seq: u64) {
        self.record_numbers
            .push(RecordNumber {
                epoch: epoch as u64,
                seq,
            });
    }

    pub(crate) fn from_record_data(data: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::init(data);

        let ack = Self::read(&mut reader)?;

        if reader.any_left() {
            return Err(InvalidMessage::TrailingData("AckMessage").into());
        }
        Ok(ack)
    }

    pub(crate) fn to_records(&self) -> Vec<(u16, u64)> {
        self.record_numbers
            .iter()
            .map(|r| (r.epoch as u16, r.seq))
            .collect()
    }
}

pub(crate) fn generate_ack(received: &HashSet<(u16, u64)>) -> AckMessage {
    let mut ack = AckMessage::new();

    if received.is_empty() {
        debug!("No records to acknowledge. Sending empty ACK.");
        return ack;
    }

    let mut records: Vec<_> = received.iter().copied().collect();
    records.sort_unstable_by_key(|&(epoch, seq)| (epoch, seq));

    for (epoch, seq) in records {
        ack.add_record(epoch, seq);
    }

    debug!("Sending ACK: {:?}", ack);
    ack
}
