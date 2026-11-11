//! The dashboard's history: once a minute, each connected host's load and the
//! fleet's queued and running jobs, kept for [`RETENTION_SECS`], and read back
//! averaged into steps for a chart.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::store::MetricSample;

/// How often a sample is taken.
pub const SAMPLE_EVERY_SECS: u64 = 60;
/// How long samples are kept: the longest range a chart shows.
pub const RETENTION_SECS: i64 = 7 * 24 * 60 * 60;

/// A chart's time range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    Hour,
    SixHours,
    Day,
    Week,
}

impl Range {
    /// `1h`, `6h`, `24h` or `7d`; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "1h" => Some(Self::Hour),
            "6h" => Some(Self::SixHours),
            "24h" => Some(Self::Day),
            "7d" => Some(Self::Week),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hour => "1h",
            Self::SixHours => "6h",
            Self::Day => "24h",
            Self::Week => "7d",
        }
    }

    /// The first step's start for a chart ending at `now`, and the step.
    #[must_use]
    pub const fn window(self, now: i64) -> (i64, i64) {
        let (span, step) = self.span_and_step();
        let end = now - now.rem_euclid(step);
        (end - span + step, step)
    }

    /// Its length and one step, in seconds: at most 360 points.
    #[must_use]
    pub const fn span_and_step(self) -> (i64, i64) {
        match self {
            Self::Hour => (3600, 60),
            Self::SixHours => (6 * 3600, 60),
            Self::Day => (24 * 3600, 300),
            Self::Week => (7 * 24 * 3600, 1800),
        }
    }
}

/// One host's series.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HostSeries {
    pub id: String,
    pub name: String,
    pub cpu: Vec<Option<u32>>,
    pub ram_used: Vec<Option<u64>>,
    pub ram_total: Vec<Option<u64>>,
    pub busy: Vec<Option<u32>>,
    pub slots: Vec<Option<u32>>,
    pub disk_free: Vec<Option<u64>>,
}

/// What `/api/metrics` answers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Series {
    pub range: &'static str,
    pub step_secs: i64,
    pub t: Vec<i64>,
    pub queued: Vec<Option<u32>>,
    pub running: Vec<Option<u32>>,
    pub hosts: Vec<HostSeries>,
}

/// Averages of the samples that fell in one step.
#[derive(Debug, Default, Clone, Copy)]
struct Mean {
    sum: u128,
    count: u32,
}

impl Mean {
    fn add(&mut self, value: Option<u64>) {
        if let Some(value) = value {
            self.sum += u128::from(value);
            self.count += 1;
        }
    }

    fn get(self) -> Option<u64> {
        (self.count > 0)
            .then(|| u64::try_from(self.sum / u128::from(self.count)).unwrap_or(u64::MAX))
    }

    fn get32(self) -> Option<u32> {
        self.get()
            .map(|value| u32::try_from(value).unwrap_or(u32::MAX))
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Step {
    cpu: Mean,
    ram_used: Mean,
    ram_total: Mean,
    busy: Mean,
    slots: Mean,
    disk_free: Mean,
    queued: Mean,
    running: Mean,
}

/// `samples` (from [`crate::store::Store::metrics`]) as the chart series of
/// `range` ending at `now`; `names` gives each host id its display name. A
/// step with no sample of a host is `None` there.
#[must_use]
pub fn series(
    samples: &[MetricSample],
    range: Range,
    now: i64,
    names: &BTreeMap<String, String>,
) -> Series {
    let (span, _) = range.span_and_step();
    let (start, step) = range.window(now);
    let points = usize::try_from(span / step).unwrap_or(0);
    let index = |at: i64| -> Option<usize> {
        (at >= start)
            .then(|| usize::try_from((at - start) / step).ok())
            .flatten()
            .filter(|&index| index < points)
    };
    let mut fleet = vec![Step::default(); points];
    let mut hosts: BTreeMap<String, Vec<Step>> = BTreeMap::new();
    for sample in samples {
        let Some(at) = index(sample.at) else { continue };
        let bucket = if sample.host_id.is_empty() {
            &mut fleet[at]
        } else {
            &mut hosts
                .entry(sample.host_id.clone())
                .or_insert_with(|| vec![Step::default(); points])[at]
        };
        bucket.cpu.add(sample.cpu.map(u64::from));
        bucket.ram_used.add(sample.ram_used);
        bucket.ram_total.add(sample.ram_total);
        bucket.busy.add(sample.busy.map(u64::from));
        bucket.slots.add(sample.slots.map(u64::from));
        bucket.disk_free.add(sample.disk_free);
        bucket.queued.add(sample.queued.map(u64::from));
        bucket.running.add(sample.running.map(u64::from));
    }
    let mut hosts: Vec<HostSeries> = hosts
        .into_iter()
        .map(|(id, steps)| HostSeries {
            name: names.get(&id).cloned().unwrap_or_else(|| id.clone()),
            cpu: steps.iter().map(|step| step.cpu.get32()).collect(),
            ram_used: steps.iter().map(|step| step.ram_used.get()).collect(),
            ram_total: steps.iter().map(|step| step.ram_total.get()).collect(),
            busy: steps.iter().map(|step| step.busy.get32()).collect(),
            slots: steps.iter().map(|step| step.slots.get32()).collect(),
            disk_free: steps.iter().map(|step| step.disk_free.get()).collect(),
            id,
        })
        .collect();
    hosts.sort_by(|a, b| a.name.cmp(&b.name));
    Series {
        range: range.name(),
        step_secs: step,
        t: (0..points)
            .map(|index| start + step * i64::try_from(index).unwrap_or(0))
            .collect(),
        queued: fleet.iter().map(|step| step.queued.get32()).collect(),
        running: fleet.iter().map(|step| step.running.get32()).collect(),
        hosts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_average_into_steps_and_gaps_stay_empty() {
        let now = 10_000 * 3600;
        let sample = |at: i64, host: &str, cpu: u32| MetricSample {
            at,
            host_id: host.into(),
            cpu: Some(cpu),
            queued: host.is_empty().then_some(cpu),
            ..MetricSample::default()
        };
        let samples = [
            sample(now - 120, "h1", 10),
            sample(now - 100, "h1", 30),
            sample(now - 60, "", 4),
            sample(now - 7200, "h1", 99),
        ];
        let names = BTreeMap::from([("h1".to_owned(), "box".to_owned())]);
        let series = series(&samples, Range::Hour, now, &names);
        assert_eq!(series.t.len(), 60);
        assert_eq!(*series.t.last().unwrap(), now);
        let host = &series.hosts[0];
        assert_eq!(host.name, "box");
        assert_eq!(host.cpu[57], Some(20), "two samples in one step average");
        assert_eq!(host.cpu[58], None);
        assert_eq!(series.queued[58], Some(4));
        assert!(!host.cpu.contains(&Some(99)), "outside the range");
        assert_eq!(Range::parse("7d"), Some(Range::Week));
        assert_eq!(Range::parse("2h"), None);
    }

    #[test]
    fn the_store_averages_a_week_into_the_charts_steps() {
        let mut store = crate::store::Store::open_in_memory().expect("store");
        let now = 10_000 * 3600;
        let (start, step) = Range::Week.window(now);
        let samples: Vec<MetricSample> = (0..90)
            .map(|minute| MetricSample {
                at: start + minute * 60,
                host_id: "h1".into(),
                cpu: Some(u32::try_from(minute / 30).unwrap() * 10),
                ..MetricSample::default()
            })
            .collect();
        store.record_metrics(&samples, 0).expect("recorded");
        let rows = store.metrics(start, step).expect("read");
        assert_eq!(rows.len(), 3, "one row per half-hour step");
        assert_eq!(rows[1].at, start + step);
        let series = series(&rows, Range::Week, now, &BTreeMap::new());
        assert_eq!(&series.hosts[0].cpu[..3], &[Some(0), Some(10), Some(20)]);
        assert_eq!(series.hosts[0].cpu[3], None);
    }
}
