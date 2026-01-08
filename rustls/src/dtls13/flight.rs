use crate::dtls13::ack::{generate_ack, AckMessage};
use crate::dtls13::timer::DtlsTimer;
use crate::Error;
use std::{collections::HashSet, time::Instant, vec::Vec};

#[derive(Debug, Clone)]
pub(crate) struct Flight {
    pub(crate) datagrams: Vec<Vec<u8>>,
    pub(crate) record_numbers: Vec<(u16, u64)>,
    pub(crate) epoch: u16,
    pub(crate) first_sent: Option<Instant>,
    pub(crate) last_sent: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum FlightState {
    Preparing,
    Waiting,
    Finished,
}

pub(crate) struct FlightTracker {
    current: Option<Flight>,
    state: FlightState,
    timer: DtlsTimer,
    received_records: HashSet<(u16, u64)>, // for ACK generation
}

impl FlightTracker {
    pub(crate) fn new() -> Self {
        Self {
            current: None,
            state: FlightState::Preparing,
            timer: DtlsTimer::new(),
            received_records: HashSet::new(),
        }
    }

    pub(crate) fn start_flight(&mut self, epoch: u16) {
        self.received_records.clear();
        self.current = None;

        self.current = Some(Flight {
            datagrams: Vec::new(),
            record_numbers: Vec::new(),
            epoch,
            first_sent: None,
            last_sent: None,
        });
        self.state = FlightState::Preparing;
    }

    pub(crate) fn add_record(&mut self, datagrams: Vec<Vec<u8>>, record_nums: Vec<u64>) {
        let flight = self
            .current
            .as_mut()
            .expect("flight not started");
        for seq in record_nums {
            flight
                .record_numbers
                .push((flight.epoch, seq));
        }
        flight.datagrams.extend(datagrams);
    }

    pub(crate) fn mark_sent(&mut self) {
        let flight = self
            .current
            .as_mut()
            .expect("flight not sent");
        let now = Instant::now();
        flight.first_sent.get_or_insert(now);
        flight.last_sent = Some(now);
        self.state = FlightState::Waiting;

        // Start retransmission timer
        self.timer.start();
    }

    pub(crate) fn process_ack_payload(&mut self, ack_data: &[u8]) -> Result<(), Error> {
        let ack = AckMessage::from_record_data(ack_data)?;
        self.on_ack_ranges(&ack.to_ranges());
        Ok(())
    }

    pub(crate) fn record_received(&mut self, epoch: u16, seq: u64) {
        self.received_records
            .insert((epoch, seq));
        self.timer.stop();
    }

    pub(crate) fn generate_ack(&self) -> AckMessage {
        generate_ack(&self.received_records)
    }

    pub(crate) fn poll_timeout(&mut self) -> Option<&[Vec<u8>]> {
        if !self.timer.poll_timeout() {
            return None;
        }

        let flight = self.current.as_mut()?;

        Some(&flight.datagrams)
    }

    pub(crate) fn on_ack_ranges(&mut self, ranges: &[(u16, u64, u64)]) {
        let flight = self
            .current
            .as_mut()
            .expect("no current flight");

        // Remove acked records from retransmission set
        flight
            .record_numbers
            .retain(|&(rec_epoch, num)| {
                !ranges
                    .iter()
                    .any(|(epoch, start, end)| rec_epoch == *epoch && num >= *start && num <= *end)
            });

        if flight.record_numbers.is_empty() {
            self.finish();
        }
    }

    pub(crate) fn finish(&mut self) {
        self.state = FlightState::Finished;
        self.timer.stop();
        self.current = None;
    }
}
