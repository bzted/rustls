use core::time::Duration;
use std::time::Instant;

pub(crate) struct DtlsTimer {
    base_timeout: Duration,
    max_timeout: Duration,
    current_timeout: Duration,
    started_at: Option<Instant>,
    attempt: u32,
    active: bool,
}

impl DtlsTimer {
    pub(crate) fn new() -> Self {
        Self {
            base_timeout: Duration::from_millis(1000),
            max_timeout: Duration::from_secs(60),
            current_timeout: Duration::from_millis(1000),
            started_at: None,
            attempt: 0,
            active: false,
        }
    }

    pub(crate) fn start(&mut self) {
        self.attempt += 1;
        let multiplier = 2u32.saturating_pow(self.attempt.saturating_sub(1));
        self.current_timeout = self
            .base_timeout
            .saturating_mul(multiplier)
            .min(self.max_timeout);

        self.started_at = Some(Instant::now());
        self.active = true;
    }

    pub(crate) fn stop(&mut self) {
        self.active = false;
        self.attempt = 0;
        self.started_at = None;
    }

    pub(crate) fn poll_timeout(&mut self) -> bool {
        if !self.active {
            return false;
        }

        if let Some(started) = self.started_at {
            if started.elapsed() >= self.current_timeout {
                return true;
            }
        }
        false
    }
}
