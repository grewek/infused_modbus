//! Diffs a machine's current Sparkplug metric list (built fresh each poll
//! tick by `client::sparkplug_translator::build_machine_metrics`) against
//! what was last actually published, so `NDATA`/`DDATA` only ever carry
//! metrics whose value genuinely changed — per CLAUDE.md's M6 scope
//! ("incremental value publishing on change"). Keyed by alias rather than
//! `(machine_name, metric_name)`: `client::sparkplug_alias::AliasAllocator`
//! already guarantees every alias is unique across the whole Edge Node, so
//! one flat map suffices regardless of which machine a metric belongs to.

use sparkplug::metric::Metric;
use sparkplug::metric_value::MetricValue;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct ChangeTracker {
    last_published: HashMap<u64, MetricValue>,
}

impl ChangeTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the subset of `metrics` whose value differs from what this
    /// tracker last recorded for the same alias (or that have never been
    /// recorded at all), then records their new value as the latest known
    /// state. Metrics whose value is unchanged are silently dropped — the
    /// whole point of this type. Panics if a metric has no alias: every real
    /// metric `build_machine_metrics` produces always carries one, so a
    /// missing alias here is a genuine caller bug, not an expected case.
    pub fn changed_metrics(&mut self, metrics: &[Metric]) -> Vec<Metric> {
        let mut changed = Vec::new();
        for metric in metrics {
            let alias = metric
                .alias
                .expect("every metric built for publishing must carry its assigned alias");
            let is_changed = self.last_published.get(&alias) != Some(&metric.value);
            if is_changed {
                self.last_published.insert(alias, metric.value.clone());
                changed.push(metric.clone());
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sparkplug::data_type::DataType;

    fn metric(alias: u64, value: MetricValue) -> Metric {
        Metric {
            name: "Tank_Temperature".to_string(),
            alias: Some(alias),
            timestamp: None,
            data_type: DataType::UInt16,
            value,
        }
    }

    #[test]
    fn first_call_reports_every_metric_as_changed() {
        let mut tracker = ChangeTracker::new();
        let metrics = vec![
            metric(0, MetricValue::Int(21)),
            metric(1, MetricValue::Int(5)),
        ];

        let changed = tracker.changed_metrics(&metrics);
        assert_eq!(changed, metrics);
    }

    #[test]
    fn unchanged_values_are_not_reported_on_a_later_call() {
        let mut tracker = ChangeTracker::new();
        let metrics = vec![metric(0, MetricValue::Int(21))];
        tracker.changed_metrics(&metrics);

        let changed = tracker.changed_metrics(&metrics);
        assert!(changed.is_empty());
    }

    #[test]
    fn a_metric_whose_value_changed_is_reported_again() {
        let mut tracker = ChangeTracker::new();
        tracker.changed_metrics(&[metric(0, MetricValue::Int(21))]);

        let changed = tracker.changed_metrics(&[metric(0, MetricValue::Int(22))]);
        assert_eq!(changed, vec![metric(0, MetricValue::Int(22))]);
    }

    #[test]
    fn only_the_changed_metric_among_several_is_reported() {
        let mut tracker = ChangeTracker::new();
        tracker.changed_metrics(&[
            metric(0, MetricValue::Int(21)),
            metric(1, MetricValue::Int(5)),
        ]);

        let changed = tracker.changed_metrics(&[
            metric(0, MetricValue::Int(21)),
            metric(1, MetricValue::Int(9)),
        ]);
        assert_eq!(changed, vec![metric(1, MetricValue::Int(9))]);
    }

    #[test]
    #[should_panic(expected = "must carry its assigned alias")]
    fn panics_on_a_metric_without_an_alias() {
        let mut tracker = ChangeTracker::new();
        let mut metric_without_alias = metric(0, MetricValue::Int(21));
        metric_without_alias.alias = None;
        tracker.changed_metrics(&[metric_without_alias]);
    }
}
