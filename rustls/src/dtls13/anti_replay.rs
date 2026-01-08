use log::debug;

pub(crate) struct AntiReplayWindow {
    bitmap: u64,
    last_seq: u64,
}

impl AntiReplayWindow {
    const WINDOW_SIZE: u64 = 64;

    pub(crate) fn new() -> Self {
        Self {
            bitmap: 0,
            last_seq: 0,
        }
    }

    /// Check if a sequence number is valid
    pub(crate) fn check(&mut self, seq: u64) -> bool {
        // First packet, accept
        if self.last_seq == 0 && self.bitmap == 0 {
            self.bitmap = 1;
            self.last_seq = seq;
            return true;
        }

        if seq > self.last_seq {
            let gap = seq - self.last_seq;

            if gap >= Self::WINDOW_SIZE {
                self.bitmap = 1;
                self.last_seq = seq;
            } else {
                self.bitmap = self
                    .bitmap
                    .checked_shl(gap as u32)
                    .unwrap_or(0);
                self.bitmap |= 1;
                self.last_seq = seq;
            }
            return true;
        }

        let diff = self.last_seq - seq; // bit position
        if diff >= Self::WINDOW_SIZE {
            debug!(
                "Bit position out of range, seq: {:?}, diff: {:?}",
                seq, diff
            );
            return false;
        }

        let mask = 1u64 << diff;

        if (self.bitmap & mask) != 0 {
            debug!("sequence number already received, replay detected");
            return false;
        }

        self.bitmap |= mask;

        true
    }

    /// read-only check()
    pub(crate) fn would_accept(&self, seq: u64) -> bool {
        if self.last_seq == 0 && self.bitmap == 0 {
            return true;
        }

        if seq > self.last_seq {
            return true;
        }

        let diff = self.last_seq - seq;
        if diff >= Self::WINDOW_SIZE {
            return false;
        }

        let mask = 1u64 << diff;
        (self.bitmap & mask) == 0
    }
    /// Reset the replay window (for epoch changes)
    pub(crate) fn reset(&mut self) {
        self.bitmap = 0;
        self.last_seq = 0;
    }

    pub(crate) fn get_last_seq(&self) -> u64 {
        self.last_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequential_packets() {
        let mut window = AntiReplayWindow::new();

        // Sequential packets should all be accepted
        assert!(window.check(1));
        assert!(window.check(2));
        assert!(window.check(3));
        assert!(window.check(4));
        assert!(window.check(5));
    }

    #[test]
    fn test_duplicate_detection() {
        let mut window = AntiReplayWindow::new();

        assert!(window.check(1));
        assert!(window.check(2));
        assert!(window.check(3));

        // Duplicates should be rejected
        assert!(!window.check(2)); // Replay
        assert!(!window.check(1)); // Replay
        assert!(!window.check(3)); // Replay
    }

    #[test]
    fn test_out_of_order_within_window() {
        let mut window = AntiReplayWindow::new();

        assert!(window.check(1));
        assert!(window.check(3));
        assert!(window.check(5));

        // Out of order but new packets within window should be accepted
        assert!(window.check(2));
        assert!(window.check(4));

        // But duplicates should still be rejected
        assert!(!window.check(2));
        assert!(!window.check(4));
    }

    #[test]
    fn test_window_sliding() {
        let mut window = AntiReplayWindow::new();

        // Establish a window
        for i in 1..=65 {
            assert!(window.check(i));
        }

        // Packet 1 should now be outside the window (too old)
        assert!(!window.check(1));

        // Packet 2 should still be in the window
        assert!(!window.check(2)); // It's a duplicate, but within window

        // Jump forward
        assert!(window.check(100));

        // Now packets 1-35 should all be too old
        for i in 1..=35 {
            assert!(!window.check(i));
        }
    }

    #[test]
    fn test_large_gap() {
        let mut window = AntiReplayWindow::new();

        assert!(window.check(1));
        assert!(window.check(1000)); // Large jump

        // Everything before 937 (1000 - 63) should be rejected as too old
        assert!(!window.check(936));
        assert!(window.check(937));
        assert!(window.check(950));
    }

    #[test]
    fn test_would_accept() {
        let mut window = AntiReplayWindow::new();

        // would_accept doesn't modify state
        assert!(window.would_accept(1));
        assert!(window.would_accept(1)); // Still returns true

        // Now actually accept it
        assert!(window.check(1));
        assert!(!window.would_accept(1)); // Now it returns false
    }

    #[test]
    fn test_reset() {
        let mut window = AntiReplayWindow::new();

        assert!(window.check(10));
        assert!(window.check(20));

        window.reset();

        // After reset, we can accept packet 10 again
        assert!(window.check(10));
    }
}
