//! What a runner's process tree uses right now: resident memory and CPU time
//! summed over a root process and every descendant (coordinator stage 4, job
//! weight statistics).
//!
//! One call is one cheap look, taken every few seconds by the daemon off its
//! reconcile loop:
//!
//! * **Linux** reads `/proc/<pid>/stat` for every process (parent, CPU ticks,
//!   resident pages). A native runner does not get a cgroup of its own, so
//!   the tree is the unit.
//! * **macOS** lists every PID (`proc_listallpids`), reads each parent
//!   (`PROC_PIDT_SHORTBSDINFO`, which any account may read, so a `sudo` step
//!   keeps its place in the tree) and, for the tree, `PROC_PIDTASKINFO`
//!   (resident size, user and system time in Mach ticks).
//! * **Windows** takes one Toolhelp snapshot for the parent links and, for
//!   the tree, `GetProcessMemoryInfo` (working set) and `GetProcessTimes`. A
//!   native runner is not started inside a Job Object, so there is no job
//!   accounting to read. Toolhelp keeps a dead parent's PID, which Windows
//!   soon hands to another process, so a child created before its supposed
//!   parent is not counted as its child.
//!
//! The CPU total of a tree drops when a descendant exits (except on Linux,
//! which folds a reaped child into its parent's `cutime`/`cstime`); the
//! caller adds up the increases between looks, so at most a look's worth of
//! an exiting process's time is lost. A process this account may not
//! inspect counts as using nothing. Work that leaves the tree is not seen:
//! containers run by `dockerd`, and daemons that detach (a Gradle daemon, a
//! `nohup` server) and are re-parented to init.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

/// One look at a process tree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TreeUsage {
    /// Resident memory of every process in the tree, summed.
    pub rss_bytes: u64,
    /// CPU time the tree has used, summed.
    pub cpu_time: Duration,
    /// How many processes the tree held.
    pub processes: u32,
}

/// What one process uses: resident memory and CPU time.
type Facts = (u64, Duration);

/// The tree under `root`, `root` included, or `None` when `root` is gone.
#[must_use]
pub fn sample_tree(root: u32) -> Option<TreeUsage> {
    sample_trees(&[root]).remove(&root)
}

/// The trees under each of `roots`, from one look at the process table: a
/// root that is gone has no entry.
#[must_use]
pub fn sample_trees(roots: &[u32]) -> HashMap<u32, TreeUsage> {
    if roots.is_empty() {
        return HashMap::new();
    }
    sys::sample_trees(roots)
}

/// Sums `facts` over the tree under each of `roots`, given every process's
/// `(pid, parent)`. A process `facts` cannot read counts as using nothing; a
/// cycle (a recycled PID naming a descendant as its parent) is walked once.
fn trees(
    roots: &[u32],
    parents: &[(u32, u32)],
    mut facts: impl FnMut(u32) -> Option<Facts>,
    mut is_child: impl FnMut(u32, u32) -> bool,
) -> HashMap<u32, TreeUsage> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, parent) in parents {
        if pid != parent {
            children.entry(*parent).or_default().push(*pid);
        }
    }
    let alive: HashSet<u32> = parents.iter().map(|(pid, _)| *pid).collect();
    let mut found = HashMap::new();
    for root in roots.iter().copied().filter(|root| alive.contains(root)) {
        let mut usage = TreeUsage::default();
        let mut seen = HashSet::from([root]);
        let mut queue = VecDeque::from([root]);
        while let Some(pid) = queue.pop_front() {
            let (rss, cpu) = facts(pid).unwrap_or_default();
            usage.rss_bytes = usage.rss_bytes.saturating_add(rss);
            usage.cpu_time = usage.cpu_time.saturating_add(cpu);
            usage.processes = usage.processes.saturating_add(1);
            for child in children.get(&pid).into_iter().flatten() {
                if !seen.contains(child) && is_child(*child, pid) {
                    seen.insert(*child);
                    queue.push_back(*child);
                }
            }
        }
        found.insert(root, usage);
    }
    found
}

/// Fields of one `/proc/<pid>/stat` line: the parent, the CPU ticks the
/// process and its waited-for children used, and its resident pages. The
/// command name may hold spaces and parentheses, so the fields are counted
/// from the last `)` ([`crate::process::proc_stat_after_comm`]).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_stat(line: &str) -> Option<(u32, u64, u64)> {
    let fields: Vec<&str> = crate::process::proc_stat_after_comm(line)?
        .split_whitespace()
        .collect();
    // After the name: state(3) ppid(4) ... utime(14) stime(15) cutime(16)
    // cstime(17) ... rss(24); index 0 here is field 3.
    let field = |number: usize| fields.get(number - 3).copied();
    if matches!(field(3)?, "Z" | "X" | "x") {
        return None;
    }
    let parent = field(4)?.parse().ok()?;
    let ticks = [14, 15, 16, 17]
        .into_iter()
        .map(|number| field(number)?.parse::<i64>().ok())
        .try_fold(0u64, |sum, value| {
            Some(sum.saturating_add(u64::try_from(value?).unwrap_or(0)))
        })?;
    let pages = u64::try_from(field(24)?.parse::<i64>().ok()?).unwrap_or(0);
    Some((parent, ticks, pages))
}

#[cfg(target_os = "linux")]
mod sys {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::{Facts, TreeUsage, parse_proc_stat, trees};

    pub(super) fn sample_trees(roots: &[u32]) -> HashMap<u32, TreeUsage> {
        // SAFETY: `sysconf` reads a constant and cannot fail in a way that
        // matters here; a non-positive answer is replaced below.
        let ticks_per_second = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
            .ok()
            .filter(|ticks| *ticks > 0)
            .unwrap_or(100);
        // SAFETY: as above.
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|page| *page > 0)
            .unwrap_or(4096);
        let mut parents = Vec::new();
        let mut facts: HashMap<u32, Facts> = HashMap::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return HashMap::new();
        };
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            // Gone meanwhile, or not readable: skipped.
            let Ok(line) = std::fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            if let Some((parent, ticks, pages)) = parse_proc_stat(&line) {
                parents.push((pid, parent));
                facts.insert(
                    pid,
                    (
                        pages.saturating_mul(page),
                        Duration::from_nanos(
                            ticks.saturating_mul(1_000_000_000) / ticks_per_second,
                        ),
                    ),
                );
            }
        }
        trees(roots, &parents, |pid| facts.get(&pid).copied(), |_, _| true)
    }
}

#[cfg(target_os = "macos")]
mod sys {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::{TreeUsage, trees};

    fn info<T>(pid: i32, flavor: i32) -> Option<T> {
        let size = i32::try_from(std::mem::size_of::<T>()).ok()?;
        let mut value = std::mem::MaybeUninit::<T>::zeroed();
        // SAFETY: `value` is a zeroed buffer of exactly `size` bytes for the
        // plain-data structure `flavor` fills; the call writes at most that.
        let written =
            unsafe { libc::proc_pidinfo(pid, flavor, 0, value.as_mut_ptr().cast(), size) };
        // SAFETY: the kernel filled the whole structure (`written == size`),
        // and zeroed is a valid value of these plain-data types anyway.
        (written == size).then(|| unsafe { value.assume_init() })
    }

    /// Mach ticks to nanoseconds: `PROC_PIDTASKINFO` times are in ticks,
    /// which are nanoseconds on Intel and not on Apple silicon.
    #[allow(
        deprecated,
        reason = "libc marks the mach bindings deprecated in favour of a crate this workspace does not take; the call is stable"
    )]
    fn ticks_to_nanos(ticks: u64) -> u64 {
        static BASE: std::sync::OnceLock<(u32, u32)> = std::sync::OnceLock::new();
        let (numer, denom) = *BASE.get_or_init(|| {
            let mut base = libc::mach_timebase_info { numer: 0, denom: 0 };
            // SAFETY: `base` is a live structure owned by this frame.
            let ok = unsafe { libc::mach_timebase_info(&raw mut base) } == 0;
            if ok && base.denom != 0 {
                (base.numer, base.denom)
            } else {
                (1, 1)
            }
        });
        u64::try_from(u128::from(ticks) * u128::from(numer) / u128::from(denom)).unwrap_or(u64::MAX)
    }

    fn all_pids() -> Vec<i32> {
        // SAFETY: a null buffer asks for the count only.
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        let Ok(count) = usize::try_from(count) else {
            return Vec::new();
        };
        // Room for processes started since the count.
        let mut pids = vec![0i32; count + 64];
        let bytes = i32::try_from(pids.len() * std::mem::size_of::<i32>()).unwrap_or(i32::MAX);
        // SAFETY: `pids` holds `bytes` bytes and outlives the call.
        let filled = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        pids.truncate(usize::try_from(filled).unwrap_or(0).min(pids.len()));
        pids
    }

    pub(super) fn sample_trees(roots: &[u32]) -> HashMap<u32, TreeUsage> {
        let parents: Vec<(u32, u32)> = all_pids()
            .into_iter()
            .filter(|pid| *pid > 0)
            .filter_map(|pid| {
                let bsd: libc::proc_bsdshortinfo = info(pid, libc::PROC_PIDT_SHORTBSDINFO)?;
                Some((u32::try_from(pid).ok()?, bsd.pbsi_ppid))
            })
            .collect();
        trees(
            roots,
            &parents,
            |pid| {
                let task: libc::proc_taskinfo =
                    info(i32::try_from(pid).ok()?, libc::PROC_PIDTASKINFO)?;
                Some((
                    task.pti_resident_size,
                    Duration::from_nanos(ticks_to_nanos(
                        task.pti_total_user.saturating_add(task.pti_total_system),
                    )),
                ))
            },
            |_, _| true,
        )
    }
}

#[cfg(windows)]
mod sys {
    use std::collections::HashMap;
    use std::time::Duration;

    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{Facts, TreeUsage, trees};

    fn parents() -> Vec<(u32, u32)> {
        // SAFETY: a process snapshot takes no pointer; the handle is closed
        // below exactly once.
        let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
            return Vec::new();
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(0),
            ..PROCESSENTRY32W::default()
        };
        let mut pairs = Vec::new();
        // SAFETY: `entry` is a live, size-stamped structure owned by this
        // frame, and `snapshot` is open.
        let mut more = unsafe { Process32FirstW(snapshot, &raw mut entry) }.is_ok();
        while more {
            pairs.push((entry.th32ProcessID, entry.th32ParentProcessID));
            // SAFETY: as above.
            more = unsafe { Process32NextW(snapshot, &raw mut entry) }.is_ok();
        }
        // SAFETY: opened above, closed once.
        let _ = unsafe { CloseHandle(snapshot) };
        pairs
    }

    /// A `FILETIME` in 100 ns units.
    fn hundreds(time: FILETIME) -> u64 {
        (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
    }

    fn filetime(time: FILETIME) -> Duration {
        Duration::from_nanos(hundreds(time).saturating_mul(100))
    }

    /// What one process uses, and when it was created; `None` when this
    /// account cannot open it.
    fn facts(pid: u32) -> Option<(Facts, Option<u64>)> {
        // SAFETY: a plain call; the handle is closed below exactly once.
        // Querying memory and times needs no more than limited information.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let mut memory = PROCESS_MEMORY_COUNTERS {
            cb: u32::try_from(std::mem::size_of::<PROCESS_MEMORY_COUNTERS>()).unwrap_or(0),
            ..PROCESS_MEMORY_COUNTERS::default()
        };
        // SAFETY: `memory` is a live, size-stamped structure owned by this
        // frame; `handle` is open.
        let rss = if unsafe { GetProcessMemoryInfo(handle, &raw mut memory, memory.cb) }.is_ok() {
            u64::try_from(memory.WorkingSetSize).unwrap_or(u64::MAX)
        } else {
            0
        };
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: four live out-parameters owned by this frame.
        let timed = unsafe {
            GetProcessTimes(
                handle,
                &raw mut created,
                &raw mut exited,
                &raw mut kernel,
                &raw mut user,
            )
        };
        let (cpu, born) = if timed.is_ok() {
            (
                filetime(kernel).saturating_add(filetime(user)),
                Some(hundreds(created)),
            )
        } else {
            (Duration::ZERO, None)
        };
        // SAFETY: opened above, closed once.
        let _ = unsafe { CloseHandle(handle) };
        Some(((rss, cpu), born))
    }

    pub(super) fn sample_trees(roots: &[u32]) -> HashMap<u32, TreeUsage> {
        let known = std::cell::RefCell::new(HashMap::<u32, Option<(Facts, Option<u64>)>>::new());
        let look = |pid: u32| *known.borrow_mut().entry(pid).or_insert_with(|| facts(pid));
        trees(
            roots,
            &parents(),
            |pid| look(pid).map(|(facts, _)| facts),
            // A child created before its parent names a dead parent whose
            // PID was reused: not this tree's.
            |child, parent| match (look(child), look(parent)) {
                (Some((_, Some(child))), Some((_, Some(parent)))) => child >= parent,
                _ => true,
            },
        )
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod sys {
    use std::collections::HashMap;

    use super::TreeUsage;

    pub(super) fn sample_trees(_: &[u32]) -> HashMap<u32, TreeUsage> {
        HashMap::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stat_line_parses_whatever_the_command_name_holds() {
        let line = "4242 (Runner.Worker (x) 1) S 4200 4242 4200 0 -1 4194560 100 0 0 0 \
                    250 50 7 3 20 0 12 0 123456 1048576000 25600 18446744073709551615";
        assert_eq!(parse_proc_stat(line), Some((4200, 310, 25600)));
        assert_eq!(parse_proc_stat("garbage"), None);
        assert_eq!(parse_proc_stat("1 (init) S"), None);
    }

    #[test]
    fn a_tree_sums_its_descendants_only_and_survives_a_cycle() {
        let parents = [
            (1, 0),
            (10, 1),
            (11, 10),
            (12, 11),
            (20, 1),
            (30, 12),
            (12, 30),
        ];
        let facts: HashMap<u32, Facts> = [
            (1, (1, 1)),
            (10, (100, 10)),
            (11, (20, 2)),
            (12, (30, 3)),
            (20, (999, 99)),
            (30, (5, 1)),
        ]
        .into_iter()
        .map(|(pid, (rss, secs))| (pid, (rss, Duration::from_secs(secs))))
        .collect();
        let found = trees(
            &[10, 99],
            &parents,
            |pid| facts.get(&pid).copied(),
            |_, _| true,
        );
        assert_eq!(
            found,
            HashMap::from([(
                10,
                TreeUsage {
                    rss_bytes: 155,
                    cpu_time: Duration::from_secs(16),
                    processes: 4,
                }
            )]),
            "the gone root 99 has no entry"
        );
        // An unreadable process still counts as one of the tree.
        let unreadable = trees(&[10], &parents, |_| None, |_, _| true);
        assert_eq!(unreadable[&10].processes, 4);
        // A link the platform disowns (a stale parent PID) cuts that subtree.
        let cut = trees(
            &[10],
            &parents,
            |pid| facts.get(&pid).copied(),
            |child, _| child != 11,
        );
        assert_eq!(cut[&10].processes, 1);
    }

    #[test]
    fn a_stat_line_of_a_process_that_exited_is_not_a_process() {
        let line = |state: &str| {
            format!("7 (run.sh) {state} 1 7 7 0 -1 0 0 0 0 0 5 6 7 8 20 0 1 0 100 4096 42 0")
        };
        assert!(parse_proc_stat(&line("S")).is_some());
        assert_eq!(parse_proc_stat(&line("Z")), None);
        assert_eq!(parse_proc_stat(&line("X")), None);
    }

    /// A runner that exited stays in the process table until its parent reaps
    /// it, and nothing reaps it but the pass this look exists to bring forward. So
    /// it has to read as gone, or a slot waits for the next scheduled poll.
    #[test]
    fn a_process_that_exited_and_was_not_reaped_is_gone() {
        #[cfg(unix)]
        let mut child = std::process::Command::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("sh starts");
        #[cfg(windows)]
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .expect("cmd starts");
        let root = child.id();
        let mut gone = false;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            if sample_tree(root).is_none() {
                gone = true;
                break;
            }
        }
        let reaped = child.wait();
        assert!(reaped.is_ok(), "it was still ours to reap: {reaped:?}");
        assert!(gone, "an exited process still reads as running");
    }

    /// A real child tree of this process: the measurement on the current OS.
    #[cfg(unix)]
    #[test]
    fn a_spawned_process_tree_is_measured_on_this_os() {
        // A shell that starts a second process and burns some CPU, so both
        // the tree and its CPU time are non-trivial.
        let mut child = std::process::Command::new("sh")
            .args([
                "-c",
                "sleep 30 & i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done; wait",
            ])
            .spawn()
            .expect("sh starts");
        let root = child.id();
        let mut best = None;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            if let Some(usage) = sample_tree(root)
                && usage.processes >= 2
                && usage.cpu_time > Duration::ZERO
            {
                best = Some(usage);
                break;
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        let usage = best.expect("the tree was seen with its child and some CPU");
        assert!(usage.rss_bytes > 0, "{usage:?}");
        assert_eq!(sample_tree(root), None, "a reaped root is gone");
    }

    #[cfg(windows)]
    #[test]
    fn a_spawned_process_tree_is_measured_on_this_os() {
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "ping -n 6 127.0.0.1 > NUL"])
            .spawn()
            .expect("cmd starts");
        let root = child.id();
        let mut best = None;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            if let Some(usage) = sample_tree(root)
                && usage.processes >= 2
            {
                best = Some(usage);
                break;
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        let usage = best.expect("the tree was seen with its child");
        assert!(usage.rss_bytes > 0, "{usage:?}");
    }
}
