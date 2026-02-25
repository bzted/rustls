use log::debug;

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

pub(crate) struct FlightTracker {
    current: Option<Flight>,
    timer: DtlsTimer,
    received_records: HashSet<(u16, u64)>, // for ACK generation
}

impl FlightTracker {
    pub(crate) fn new() -> Self {
        Self {
            current: None,
            timer: DtlsTimer::new(),
            received_records: HashSet::new(),
        }
    }

    pub(crate) fn start_flight(&mut self, epoch: u16) {
        self.received_records.clear();

        if let Some(flight) = &mut self.current {
            flight.epoch = epoch; 
        } else {
            self.current = Some(Flight {
                datagrams: Vec::new(),
                record_numbers: Vec::new(),
                epoch,
                first_sent: None,
                last_sent: None,
            });
        }
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
        debug!("Records added for retransmision: {:?}", flight.record_numbers);
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

        // Start retransmission timer
        self.timer.start();
    }

    pub(crate) fn process_ack_payload(&mut self, ack_data: &[u8]) -> Result<(), Error> {
        let ack = AckMessage::from_record_data(ack_data)?;
        debug!("Received ACK: {:?}", ack);
        self.on_ack_records(&ack.to_records());
        Ok(())
    }

    pub(crate) fn record_received(&mut self, epoch: u16, seq: u64) {
        // We received a record, meaning peer received all our previous messages
        // clear the retransmission set
        self.current = None;
        // Add the received record to de ackable records set
        self.received_records
            .insert((epoch, seq));
        debug!("Adding received record. Epoch: {:?}, seq: {:?}. Received records: {:?}", epoch, seq, self.received_records);
        self.timer.stop();
    }

    pub(crate) fn generate_ack(&mut self) -> AckMessage {
        generate_ack(&self.received_records)
    }

    pub(crate) fn timeout(&mut self) -> Option<&[Vec<u8>]> {
        if !self.timer.timeout() {
            return None;
        }

        let flight = self.current.as_mut()?;

        Some(&flight.datagrams)
    }

    pub(crate) fn pending_datagrams(&mut self) -> Option<&[Vec<u8>]> {
        let flight = self.current.as_mut()?;
        Some(&flight.datagrams)
    }

    pub(crate) fn on_ack_records(&mut self, acked_records: &[(u16, u64)]) {
        let flight = match self.current.as_mut() {
            Some(f) => f,
            None => {
                debug!("Received ACK but no current flight to clear");
                return;
            }
        };

        // Remove acked records from retransmission set
        let mut i = 0;
        while i < flight.record_numbers.len() {
            let (rec_epoch, num) = flight.record_numbers[i];
            
            let is_acked = acked_records.iter().any(|&(ack_epoch, ack_seq)| {
                rec_epoch == ack_epoch && num == ack_seq
            });

            if is_acked {
                flight.record_numbers.remove(i);
                flight.datagrams.remove(i); 
            } else {
                i += 1;
            }
        }

        debug!("Pending records for retransmission after processing peer ACK: {:?}", flight.record_numbers);
        if flight.record_numbers.is_empty() {
            self.finish();
        } 
    }

    pub(crate) fn finish(&mut self) {
        self.timer.stop();
        self.current = None;
    }
}
