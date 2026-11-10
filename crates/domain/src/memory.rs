//! Host memory admission: whether this machine has the memory for one more
//! runner attempt.
//!
//! The coordinator filters hosts by memory only for the pool jobs it places.
//! A host's own demand (a repository or selector label) was bounded only by
//! `host_capacity` and each profile's `max_capacity`, so a 24 GiB machine
//! could start an 11.8 GiB build beside four 5.9 GiB ones. This module is the
//! rule the daemon applies before **every** start, whoever asked for it:
//!
//! ```text
//! reserved  = Σ over the attempts on the host: max(0, estimate − current RSS)
//! admit     ⇔ free − reserved ≥ estimate + margin
//! ```
//!
//! # Why the reservation is "estimate less what is already visible"
//!
//! `free` is what the operating system says is available now, so it already
//! excludes what each running attempt uses **now**. What it does not show is
//! what those attempts are still going to use: a build's peak often comes
//! minutes after it started (the link step, the test run). So each running
//! attempt holds, until it ends, the part of its estimate that has not shown
//! up yet. An attempt just started (no sample yet) holds its whole estimate;
//! one at or past its estimate holds nothing more, because its usage is in
//! `free` already.
//!
//! The alternative, a reservation that lapses some seconds after a start,
//! releases exactly when it is needed: the coordinator learned that a build's
//! peak can come long after its lease closed. Holding until the end, less what
//! is visible, never counts the same byte twice and never forgets a peak to
//! come, and it is never less strict than "total memory less every running
//! estimate", the coordinator's second test.
//!
//! # Nothing running: always admitted
//!
//! A job bigger than the machine must still run somewhere: with no attempt on
//! the host, nothing would ever free memory for it, so it is admitted (and the
//! caller warns). Memory held by things other than runners is not waited out.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The margin kept free beyond the estimate, unless configured.
pub const DEFAULT_MARGIN_BYTES: u64 = 1 << 30;

/// The memory an attempt is assumed to need when nothing is known about the
/// jobs its profile takes.
pub const DEFAULT_ESTIMATE_BYTES: u64 = 1 << 30;

/// How many of a profile's newest peaks the local estimate is taken from.
pub const LOCAL_PEAKS_KEPT: usize = 20;

/// How many of the newest peaks the estimate never falls below: a p90 over a
/// long history answers slowly when a job turns heavy.
const RECENT_PEAKS: usize = 3;

const GIB: f64 = (1u64 << 30) as f64;

/// Where an estimate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EstimateSource {
    /// The coordinator's statistics for the profile's target.
    Coordinator,
    /// This host's own measured peaks for the profile.
    Local,
    /// Nothing known: [`DEFAULT_ESTIMATE_BYTES`].
    Default,
}

impl EstimateSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::Local => "local",
            Self::Default => "default",
        }
    }
}

impl fmt::Display for EstimateSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one attempt of a profile is expected to need at its peak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estimate {
    pub bytes: u64,
    pub source: EstimateSource,
}

impl Estimate {
    /// The first estimate known: the coordinator's, else this host's own,
    /// else the default.
    #[must_use]
    pub fn choose(coordinator: Option<u64>, local: Option<u64>) -> Self {
        match (coordinator, local) {
            (Some(bytes), _) => Self {
                bytes,
                source: EstimateSource::Coordinator,
            },
            (None, Some(bytes)) => Self {
                bytes,
                source: EstimateSource::Local,
            },
            (None, None) => Self {
                bytes: DEFAULT_ESTIMATE_BYTES,
                source: EstimateSource::Default,
            },
        }
    }
}

/// The estimate from a profile's measured peaks, oldest first: their p90
/// (nearest rank), or more if one of the newest [`RECENT_PEAKS`] needed more.
/// `None` without any.
#[must_use]
pub fn local_estimate(peaks: &[u64]) -> Option<u64> {
    let p90 = percentile(peaks, 90)?;
    peaks
        .iter()
        .rev()
        .take(RECENT_PEAKS)
        .copied()
        .chain([p90])
        .max()
}

/// The `p`th percentile of `values` by nearest rank; `None` when empty.
#[must_use]
pub fn percentile(values: &[u64], p: u32) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = (sorted.len() * p.min(100) as usize).div_ceil(100).max(1);
    sorted.get(rank - 1).copied()
}

/// One attempt already on the host, as admission weighs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Running {
    /// Its profile's estimate.
    pub estimate: u64,
    /// What its process tree uses now, when it was sampled. `None` (just
    /// started, isolated, or not sampled yet) holds the whole estimate.
    pub current_rss: Option<u64>,
}

/// What the attempts on the host may still grow into: the part of each
/// estimate their current usage does not show yet.
#[must_use]
pub fn reserved(running: &[Running]) -> u64 {
    running.iter().fold(0u64, |total, attempt| {
        total.saturating_add(
            attempt
                .estimate
                .saturating_sub(attempt.current_rss.unwrap_or(0)),
        )
    })
}

/// The figures behind one decision, in bytes, for the log and `status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFigures {
    pub free: u64,
    pub reserved: u64,
    pub estimate: Estimate,
    pub margin: u64,
}

impl MemoryFigures {
    /// What a start needs available: the estimate and the margin.
    #[must_use]
    pub const fn needed(&self) -> u64 {
        self.estimate.bytes.saturating_add(self.margin)
    }

    /// What a start can count on: free memory less the reservations.
    #[must_use]
    pub const fn available(&self) -> u64 {
        self.free.saturating_sub(self.reserved)
    }
}

impl fmt::Display for MemoryFigures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "needs {} ({} {} estimate + {} margin), {} free less {} reserved",
            gib(self.needed()),
            gib(self.estimate.bytes),
            self.estimate.source,
            gib(self.margin),
            gib(self.free),
            gib(self.reserved),
        )
    }
}

/// Bytes as GiB with one decimal, the unit operators think in here.
#[must_use]
pub fn gib(bytes: u64) -> String {
    #[allow(
        clippy::cast_precision_loss,
        reason = "display only: a tenth of a GiB is the precision shown"
    )]
    let value = bytes as f64 / GIB;
    format!("{value:.1} GiB")
}

/// What admission decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryVerdict {
    /// Admission is off, or free memory cannot be read here.
    Unchecked,
    /// The start fits.
    Admit(MemoryFigures),
    /// It does not fit, but nothing runs on the host that could free memory:
    /// admitted so that a job bigger than the machine is not starved.
    AdmitAlone(MemoryFigures),
    /// It does not fit: the demand stays queued for a later pass.
    Defer(MemoryFigures),
}

impl MemoryVerdict {
    #[must_use]
    pub const fn admits(&self) -> bool {
        !matches!(self, Self::Defer(_))
    }

    #[must_use]
    pub const fn figures(&self) -> Option<&MemoryFigures> {
        match self {
            Self::Unchecked => None,
            Self::Admit(figures) | Self::AdmitAlone(figures) | Self::Defer(figures) => {
                Some(figures)
            }
        }
    }
}

/// The admission rule. `free` is `None` where free memory cannot be read:
/// nothing is decided then.
#[must_use]
pub fn admit(
    free: Option<u64>,
    running: &[Running],
    estimate: Estimate,
    margin: u64,
) -> MemoryVerdict {
    let Some(free) = free else {
        return MemoryVerdict::Unchecked;
    };
    let figures = MemoryFigures {
        free,
        reserved: reserved(running),
        estimate,
        margin,
    };
    if figures.available() >= figures.needed() {
        MemoryVerdict::Admit(figures)
    } else if running.is_empty() {
        MemoryVerdict::AdmitAlone(figures)
    } else {
        MemoryVerdict::Defer(figures)
    }
}

/// Whether admission is on, and its margin: `host set-memory-margin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemorySettings {
    pub enabled: bool,
    pub margin_bytes: u64,
}

impl Default for MemorySettings {
    fn default() -> Self {
        Self {
            enabled: true,
            margin_bytes: DEFAULT_MARGIN_BYTES,
        }
    }
}

/// `1GiB`, `512MiB`, `2G`, `1.5GB`, `800M` or a bare number of bytes, as
/// bytes. Units are binary whatever they are spelled (`G` = `GB` = `GiB`):
/// memory is counted in powers of two.
///
/// # Errors
/// Anything else, or a value that does not fit in `u64`.
pub fn parse_size(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let invalid = || format!("`{text}` is not a size; write it as `1GiB`, `512MiB` or `2G`");
    let split = text
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    if number.is_empty() {
        return Err(invalid());
    }
    let shift = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 0,
        "k" | "kb" | "kib" => 10,
        "m" | "mb" | "mib" => 20,
        "g" | "gb" | "gib" => 30,
        "t" | "tb" | "tib" => 40,
        _ => return Err(invalid()),
    };
    let value: f64 = number.parse().map_err(|_| invalid())?;
    #[allow(clippy::cast_precision_loss, reason = "a size typed by an operator")]
    let bytes = value * (1u64 << shift) as f64;
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "range-checked just above; a fraction of a byte is dropped"
    )]
    if bytes.is_finite() && bytes >= 0.0 && bytes < u64::MAX as f64 {
        Ok(bytes as u64)
    } else {
        Err(format!("`{text}` is too large"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn estimate(bytes: u64) -> Estimate {
        Estimate {
            bytes,
            source: EstimateSource::Local,
        }
    }

    fn running(estimate: u64, current: Option<u64>) -> Running {
        Running {
            estimate,
            current_rss: current,
        }
    }

    #[test]
    fn a_start_that_fits_is_admitted_and_one_that_does_not_is_deferred() {
        // MacM6: 24 GiB, an Unreal build (11.8 GiB) just started, 20 GiB free.
        let unreal = 11_800 << 20;
        let app = 5_900 << 20;
        let on_host = [running(unreal, Some(GIB))];
        let first_app = admit(Some(20 * GIB), &on_host, estimate(app), GIB);
        assert!(
            matches!(first_app, MemoryVerdict::Admit(_)),
            "{first_app:?}"
        );
        // The App build started, nothing sampled yet: it holds its estimate.
        let on_host = [running(unreal, Some(GIB)), running(app, None)];
        let second_app = admit(Some(19 * GIB), &on_host, estimate(app), GIB);
        let MemoryVerdict::Defer(figures) = second_app else {
            panic!("a second App build must wait: {second_app:?}");
        };
        assert_eq!(figures.reserved, (unreal - GIB) + app);
        assert_eq!(figures.needed(), app + GIB);
        assert!(figures.available() < figures.needed());
    }

    #[test]
    fn usage_already_visible_is_not_reserved_twice() {
        // An attempt at its estimate holds nothing more; past it, still nothing.
        assert_eq!(reserved(&[running(4 * GIB, Some(4 * GIB))]), 0);
        assert_eq!(reserved(&[running(4 * GIB, Some(6 * GIB))]), 0);
        assert_eq!(reserved(&[running(4 * GIB, Some(GIB))]), 3 * GIB);
        assert_eq!(reserved(&[running(4 * GIB, None)]), 4 * GIB);
    }

    #[test]
    fn nothing_running_is_always_admitted_however_big_the_job() {
        let verdict = admit(Some(8 * GIB), &[], estimate(30 * GIB), GIB);
        assert!(
            matches!(verdict, MemoryVerdict::AdmitAlone(_)),
            "{verdict:?}"
        );
        assert!(verdict.admits());
        // But not once something runs that would free memory.
        let verdict = admit(
            Some(8 * GIB),
            &[running(GIB, Some(GIB))],
            estimate(30 * GIB),
            GIB,
        );
        assert!(matches!(verdict, MemoryVerdict::Defer(_)), "{verdict:?}");
    }

    #[test]
    fn unreadable_free_memory_decides_nothing() {
        let verdict = admit(None, &[running(GIB, None)], estimate(30 * GIB), GIB);
        assert_eq!(verdict, MemoryVerdict::Unchecked);
        assert!(verdict.admits());
    }

    #[test]
    fn the_margin_is_kept_free_on_top_of_the_estimate() {
        let on_host = [running(GIB, Some(GIB))];
        assert!(admit(Some(3 * GIB), &on_host, estimate(2 * GIB), GIB).admits());
        assert!(!admit(Some(3 * GIB - 1), &on_host, estimate(2 * GIB), GIB).admits());
    }

    #[test]
    fn the_estimate_is_the_coordinators_then_the_hosts_then_the_default() {
        assert_eq!(
            Estimate::choose(Some(5), Some(7)),
            Estimate {
                bytes: 5,
                source: EstimateSource::Coordinator
            }
        );
        assert_eq!(
            Estimate::choose(None, Some(7)).source,
            EstimateSource::Local
        );
        assert_eq!(
            Estimate::choose(None, None),
            Estimate {
                bytes: DEFAULT_ESTIMATE_BYTES,
                source: EstimateSource::Default
            }
        );
    }

    #[test]
    fn the_local_estimate_is_the_p90_or_a_heavier_recent_peak() {
        assert_eq!(local_estimate(&[]), None);
        let mut peaks: Vec<u64> = (1..=20).collect();
        assert_eq!(
            local_estimate(&peaks),
            Some(20),
            "the newest is the heaviest"
        );
        peaks.reverse();
        assert_eq!(local_estimate(&peaks), Some(18), "p90 of 1..=20");
        peaks.push(100);
        assert_eq!(local_estimate(&peaks), Some(100), "a job that turned heavy");
    }

    /// MacM6, measured: 24 GiB, Unreal-MCP jobs peak at 11.8 GiB (cap 1),
    /// AI-Game-Dev-App at 5.9 GiB (cap 4), all queued at once. Each job's
    /// memory climbs to its peak over its run. By capacity alone the host
    /// starts all five (35.4 GiB at their peaks); with admission what runs at
    /// once never exceeds the machine, and every job still runs.
    #[test]
    fn a_simulated_macm6_never_starts_more_than_its_memory_holds() {
        const TOTAL: u64 = 24 * GIB;
        const BASELINE: u64 = 2 * GIB; // the OS and everything else
        let unreal = 11_800u64 << 20;
        let app = 5_900u64 << 20;
        // (estimate = the job's real peak, run time in ticks)
        let queue = [(unreal, 10u64), (app, 6), (app, 6), (app, 6), (app, 6)];

        let simulate = |admission: bool| -> (u64, u64) {
            // (peak, ticks running so far, length)
            let mut running: Vec<(u64, u64, u64)> = Vec::new();
            let mut waiting: Vec<(u64, u64)> = queue.to_vec();
            let mut worst = 0u64;
            let mut tick = 0u64;
            while !(waiting.is_empty() && running.is_empty()) {
                // A pass: start what the ceilings (and admission) allow.
                let mut still = Vec::new();
                for (estimate, len) in waiting.drain(..) {
                    let current = |&(peak, ran, len): &(u64, u64, u64)| peak * ran.min(len) / len;
                    let in_use: u64 = running.iter().map(current).sum();
                    let fits = admit(
                        Some(TOTAL - BASELINE - in_use),
                        &running
                            .iter()
                            .map(|job| Running {
                                estimate: job.0,
                                current_rss: Some(current(job)),
                            })
                            .collect::<Vec<_>>(),
                        Estimate::choose(Some(estimate), None),
                        GIB,
                    )
                    .admits();
                    if !admission || fits {
                        running.push((estimate, 0, len));
                    } else {
                        still.push((estimate, len));
                    }
                }
                waiting = still;
                // The jobs run a tick and climb towards their peaks.
                for job in &mut running {
                    job.1 += 1;
                }
                let in_use: u64 = running
                    .iter()
                    .map(|&(peak, ran, len)| peak * ran.min(len) / len)
                    .sum();
                worst = worst.max(BASELINE + in_use);
                running.retain(|&(_, ran, len)| ran < len);
                tick += 1;
            }
            (worst, tick)
        };

        let (crowded, fast) = simulate(false);
        let (admitted, slower) = simulate(true);
        assert!(
            crowded > TOTAL,
            "by capacity alone: {} on 24 GiB",
            gib(crowded)
        );
        assert!(admitted <= TOTAL, "with admission: {}", gib(admitted));
        assert!(slower > fast, "the price: jobs wait for memory");
        assert!(slower < 3 * fast, "but every job ran: {slower} ticks");
    }

    #[test]
    fn sizes_parse_in_binary_units() {
        assert_eq!(parse_size("1GiB"), Ok(GIB));
        assert_eq!(parse_size("1G"), Ok(GIB));
        assert_eq!(parse_size("1.5gb"), Ok(GIB + GIB / 2));
        assert_eq!(parse_size("512MiB"), Ok(512 << 20));
        assert_eq!(parse_size("2048"), Ok(2048));
        assert_eq!(parse_size(" 0 "), Ok(0));
        assert!(parse_size("lots").is_err());
        assert!(parse_size("1 parsec").is_err());
        assert!(parse_size("GiB").is_err());
        assert!(parse_size("99999999999TiB").is_err());
    }

    #[test]
    fn figures_read_in_gib() {
        let figures = MemoryFigures {
            free: 19 * GIB,
            reserved: 16 * GIB,
            estimate: estimate(6 * GIB),
            margin: GIB,
        };
        assert_eq!(
            figures.to_string(),
            "needs 7.0 GiB (6.0 GiB local estimate + 1.0 GiB margin), 19.0 GiB free less 16.0 GiB reserved"
        );
    }
}
