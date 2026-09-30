//! Builds the `NBIRTH`/`NDEATH` payloads that establish and tear down one
//! Edge Node connection session. Still minimal — only the `bdSeq` metric
//! every session needs, no real Modbus-derived data metrics yet (those are
//! added in M5, once a real `DeviceDescription` is wired in).

use crate::data_type::DataType;
use crate::metric::Metric;
use crate::metric_value::MetricValue;
use crate::payload::Payload;
use crate::seq_counter::SeqCounter;

const BD_SEQ_METRIC_NAME: &str = "bdSeq";

fn bd_seq_metric(bd_seq: u64) -> Metric {
    Metric {
        name: BD_SEQ_METRIC_NAME.to_string(),
        alias: None,
        data_type: DataType::UInt64,
        value: MetricValue::Long(bd_seq),
    }
}

/// Builds the `NDEATH` payload for a given `bd_seq`. Meant to be registered
/// as the MQTT Will *before* connecting, so the broker delivers it
/// automatically if the connection ever drops uncleanly — never published
/// directly by the Edge Node itself. Carries no timestamp: whenever the
/// broker actually delivers it (at some unknown future disconnect), any
/// timestamp fixed at build time would already be stale.
pub fn build_ndeath_payload(bd_seq: u64) -> Payload {
    Payload {
        timestamp: None,
        metrics: vec![bd_seq_metric(bd_seq)],
        seq: None,
    }
}

/// Builds the `NBIRTH` payload for a given `bd_seq` and `timestamp_millis`
/// (milliseconds since the Unix epoch — the caller's job to supply, keeping
/// this crate free of any wall-clock dependency of its own). Resets
/// `seq_counter` to 0 first and consumes that value, since `NBIRTH` always
/// carries `seq = 0` per spec.
pub fn build_nbirth_payload(
    bd_seq: u64,
    timestamp_millis: u64,
    seq_counter: &mut SeqCounter,
) -> Payload {
    seq_counter.reset();
    let seq = seq_counter.next_seq();
    Payload {
        timestamp: Some(timestamp_millis),
        metrics: vec![bd_seq_metric(bd_seq)],
        seq: Some(u64::from(seq)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndeath_payload_carries_only_the_bd_seq_metric() {
        let payload = build_ndeath_payload(7);
        assert_eq!(payload.timestamp, None);
        assert_eq!(payload.seq, None);
        assert_eq!(
            payload.metrics,
            vec![Metric {
                name: "bdSeq".to_string(),
                alias: None,
                data_type: DataType::UInt64,
                value: MetricValue::Long(7),
            }]
        );
    }

    #[test]
    fn nbirth_payload_carries_seq_zero_and_the_given_bd_seq() {
        let mut seq_counter = SeqCounter::new();
        let payload = build_nbirth_payload(7, 1_700_000_000_000, &mut seq_counter);
        assert_eq!(payload.timestamp, Some(1_700_000_000_000));
        assert_eq!(payload.seq, Some(0));
        assert_eq!(
            payload.metrics,
            vec![Metric {
                name: "bdSeq".to_string(),
                alias: None,
                data_type: DataType::UInt64,
                value: MetricValue::Long(7),
            }]
        );
    }

    #[test]
    fn nbirth_payload_resets_an_already_advanced_seq_counter() {
        let mut seq_counter = SeqCounter::new();
        seq_counter.next_seq();
        seq_counter.next_seq();
        seq_counter.next_seq();

        let payload = build_nbirth_payload(1, 0, &mut seq_counter);
        assert_eq!(payload.seq, Some(0));
        // the counter is primed to continue from 1 for whatever is published next
        assert_eq!(seq_counter.next_seq(), 1);
    }

    #[test]
    fn ndeath_and_nbirth_share_the_same_bd_seq_for_one_session() {
        let bd_seq = 42;
        let mut seq_counter = SeqCounter::new();
        let ndeath = build_ndeath_payload(bd_seq);
        let nbirth = build_nbirth_payload(bd_seq, 0, &mut seq_counter);
        assert_eq!(ndeath.metrics[0].value, nbirth.metrics[0].value);
    }
}
