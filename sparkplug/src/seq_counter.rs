//! Session sequence numbering: `SeqCounter` for the `seq` field on every
//! `Payload`, `BdSeqCounter` for the `bdSeq` metric that ties an `NBIRTH` to
//! its matching `NDEATH`. Related enough (both are just "the next number for
//! this session") to share one small module rather than two near-empty ones.

/// The `seq` field on every Sparkplug B `Payload` — a per-Edge-Node counter
/// that wraps at 255 back to 0, letting a host application detect a dropped
/// message from a gap in the sequence. Per spec, `NBIRTH` always restarts the
/// sequence at 0; every message after it (until the next `NBIRTH`) advances
/// by exactly 1.
#[derive(Debug, Clone, Copy, Default)]
pub struct SeqCounter {
    current: u8,
}

impl SeqCounter {
    pub fn new() -> Self {
        Self { current: 0 }
    }

    /// Returns the value to use for the next `Payload.seq`, then advances the
    /// counter (wrapping 255 -> 0).
    pub fn next_seq(&mut self) -> u8 {
        let value = self.current;
        self.current = self.current.wrapping_add(1);
        value
    }

    /// Restarts the sequence at 0 — call this when building a fresh `NBIRTH`,
    /// which always carries `seq = 0` per spec.
    pub fn reset(&mut self) {
        self.current = 0;
    }
}

/// The `bdSeq` value distinguishing one Edge Node connection session from the
/// next — included as a metric in both the `NBIRTH` sent right after
/// connecting and the `NDEATH` registered as that connection's MQTT Will, so
/// a host application can tell a genuinely new session's birth apart from a
/// stale Will belonging to a session that already ended. Doesn't wrap
/// (`u64` comfortably covers a process's whole lifetime of reconnects) and
/// isn't persisted across process restarts — no concrete need for that yet.
#[derive(Debug, Clone, Copy, Default)]
pub struct BdSeqCounter {
    next: u64,
}

impl BdSeqCounter {
    pub fn new() -> Self {
        Self { next: 0 }
    }

    /// Returns the `bdSeq` value for a new connection session, then advances.
    pub fn next_bd_seq(&mut self) -> u64 {
        let value = self.next;
        self.next += 1;
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_counter_starts_at_zero() {
        let mut counter = SeqCounter::new();
        assert_eq!(counter.next_seq(), 0);
    }

    #[test]
    fn default_counter_starts_at_zero() {
        let mut counter = SeqCounter::default();
        assert_eq!(counter.next_seq(), 0);
    }

    #[test]
    fn advances_sequentially() {
        let mut counter = SeqCounter::new();
        assert_eq!(counter.next_seq(), 0);
        assert_eq!(counter.next_seq(), 1);
        assert_eq!(counter.next_seq(), 2);
        assert_eq!(counter.next_seq(), 3);
    }

    #[test]
    fn wraps_from_255_to_0() {
        let mut counter = SeqCounter::new();
        for expected in 0..=255u8 {
            assert_eq!(counter.next_seq(), expected);
        }
        assert_eq!(counter.next_seq(), 0);
        assert_eq!(counter.next_seq(), 1);
    }

    #[test]
    fn reset_restarts_the_sequence_at_zero() {
        let mut counter = SeqCounter::new();
        counter.next_seq();
        counter.next_seq();
        counter.next_seq();
        counter.reset();
        assert_eq!(counter.next_seq(), 0);
        assert_eq!(counter.next_seq(), 1);
    }

    #[test]
    fn new_bd_seq_counter_starts_at_zero() {
        let mut counter = BdSeqCounter::new();
        assert_eq!(counter.next_bd_seq(), 0);
    }

    #[test]
    fn default_bd_seq_counter_starts_at_zero() {
        let mut counter = BdSeqCounter::default();
        assert_eq!(counter.next_bd_seq(), 0);
    }

    #[test]
    fn bd_seq_advances_by_one_per_session() {
        let mut counter = BdSeqCounter::new();
        assert_eq!(counter.next_bd_seq(), 0);
        assert_eq!(counter.next_bd_seq(), 1);
        assert_eq!(counter.next_bd_seq(), 2);
    }
}
