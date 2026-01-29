use log::debug;

use crate::dtls13::flight::FlightTracker;
use crate::error::Error;
use crate::msgs::codec::{Codec, ListLength, Reader, TlsListElement};
use crate::InvalidMessage;
use std::collections::{HashMap, HashSet};
use std::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RecordNumberRange {
    pub epoch: u64,
    pub start: u64,
    pub end: u64,
}

impl TlsListElement for RecordNumberRange {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl Codec<'_> for RecordNumberRange {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.epoch.encode(bytes);
        self.start.encode(bytes);
        self.end.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            epoch: u64::read(r)?,
            start: u64::read(r)?,
            end: u64::read(r)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct AckMessage {
    pub record_numbers: Vec<RecordNumberRange>,
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

    pub(crate) fn add_record_range(&mut self, epoch: u16, start: u64, end: u64) {
        self.record_numbers
            .push(RecordNumberRange {
                epoch: epoch as u64,
                start,
                end,
            });
    }

    pub(crate) fn from_record_data(data: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::init(data);

        let ack = Self::read(&mut reader)?;

        if !reader.any_left() {
            return Err(InvalidMessage::TrailingData("AckMessage").into());
        }
        Ok(ack)
    }

    pub(crate) fn to_ranges(&self) -> Vec<(u16, u64, u64)> {
        self.record_numbers
            .iter()
            .map(|r| (r.epoch as u16, r.start, r.end))
            .collect()
    }
}

pub(crate) fn generate_ack(received: &HashSet<(u16, u64)>) -> AckMessage {
    let mut ack = AckMessage::new();

    if received.is_empty() {
        return ack;
    }

    let mut by_epoch: HashMap<u16, Vec<u64>> = HashMap::new();
    for &(epoch, seq) in received {
        by_epoch
            .entry(epoch)
            .or_default()
            .push(seq);
    }

    for (epoch, mut seqs) in by_epoch {
        seqs.sort_unstable();

        let mut i = 0;
        while i < seqs.len() {
            let start = seqs[i];
            let mut end = start;

            while i + 1 < seqs.len() && seqs[i + 1] == end + 1 {
                end = seqs[i + 1];
                i += 1;
            }

            ack.add_record_range(epoch, start, end);
            i += 1;
        }
    }

    debug!("Sending ACK: {:?}", ack);
    ack
}
