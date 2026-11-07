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
//!   (`PROC_PIDTBSDINFO`) and, for the tree, `PROC_PIDTASKINFO` (resident
//!   size, user and system time in Mach ticks).
//! * **Windows** takes one Toolhelp snapshot for the parent links and, for
//!   the tree, `GetProcessMemoryInfo` (working set) and `GetProcessTimes`. A
//!   native runner is not started inside a Job Object, so there is no job
//!   accounting to read.
//!
//! CPU time of a descendant that exited between two looks is counted only
//! where the platform folds it into its parent (Linux `cutime`/`cstime`), so
//! the figure is a floor. A process this account may not inspect is skipped.

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

/// One process as the tree walk needs it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ProcessFacts {
    parent: u32,
    rss_bytes: u64,
    cpu_time: Duration,
}

/// The tree under `root`, `root` included, or `None` when `root` is gone.
#[must_use]
pub fn sample_tree(root: u32) -> Option<TreeUsage> {
    sys::sample_tree(root)
}

/// The PIDs of `root` and every descendant, from `(pid, parent)` pairs. A
/// cycle (a recycled PID naming a descendant as its parent) is walked once.
fn descendants(root: u32, parents: impl IntoIterator<Item = (u32, u32)>) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, parent) in parents {
        if pid != parent {
            children.entry(parent).or_default().push(pid);
        }
    }
    let mut seen = HashSet::from([root]);
    let mut order = vec![root];
    let mut queue = VecDeque::from([root]);
    while let Some(pid) = queue.pop_front() {
        for child in children.get(&pid).into_iter().flatten() {
            if seen.insert(*child) {
                order.push(*child);
                queue.push_back(*child);
            }
        }
    }
    order
}

/// Sums `facts` over the tree under `root`; `None` when `root` is not in it.
fn sum_tree(root: u32, facts: &HashMap<u32, ProcessFacts>) -> Option<TreeUsage> {
    facts.get(&root)?;
    let mut usage = TreeUsage::default();
    for pid in descendants(root, facts.iter().map(|(pid, fact)| (*pid, fact.parent))) {
        if let Some(fact) = facts.get(&pid) {
            usage.rss_bytes = usage.rss_bytes.saturating_add(fact.rss_bytes);
            usage.cpu_time = usage.cpu_time.saturating_add(fact.cpu_time);
            usage.processes = usage.processes.saturating_add(1);
        }
    }
    Some(usage)
}

/// Fields of one `/proc/<pid>/stat` line: the parent, the CPU ticks the
/// process and its waited-for children used, and its resident pages. The
/// command name is in parentheses and may hold spaces or parentheses, so the
/// fields are counted from the last `)`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_stat(line: &str) -> Option<(u32, u64, u64)> {
    let rest = &line[line.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After the name: state(3) ppid(4) ... utime(14) stime(15) cutime(16)
    // cstime(17) ... rss(24); index 0 here is field 3.
    let field = |number: usize| fields.get(number - 3).copied();
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

    use super::{ProcessFacts, TreeUsage, parse_proc_stat, sum_tree};

    pub(super) fn sample_tree(root: u32) -> Option<TreeUsage> {
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
        let mut facts = HashMap::new();
        for entry in std::fs::read_dir("/proc").ok()?.flatten() {
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
                facts.insert(
                    pid,
                    ProcessFacts {
                        parent,
                        rss_bytes: pages.saturating_mul(page),
                        cpu_time: Duration::from_nanos(
                            ticks.saturating_mul(1_000_000_000) / ticks_per_second,
                        ),
                    },
                );
            }
        }
        sum_tree(root, &facts)
    }
}

#[cfg(target_os = "macos")]
mod sys {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::{ProcessFacts, TreeUsage, descendants, sum_tree};

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
        let mut base = libc::mach_timebase_info { numer: 0, denom: 0 };
        // SAFETY: `base` is a live structure owned by this frame.
        let ok = unsafe { libc::mach_timebase_info(&raw mut base) } == 0;
        if !ok || base.denom == 0 {
            return ticks;
        }
        u64::try_from(u128::from(ticks) * u128::from(base.numer) / u128::from(base.denom))
            .unwrap_or(u64::MAX)
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

    pub(super) fn sample_tree(root: u32) -> Option<TreeUsage> {
        let parents: Vec<(u32, u32)> = all_pids()
            .into_iter()
            .filter(|pid| *pid > 0)
            .filter_map(|pid| {
                let bsd: libc::proc_bsdinfo = info(pid, libc::PROC_PIDTBSDINFO)?;
                Some((u32::try_from(pid).ok()?, bsd.pbi_ppid))
            })
            .collect();
        if !parents.iter().any(|(pid, _)| *pid == root) {
            return None;
        }
        let parent_of: HashMap<u32, u32> = parents.iter().copied().collect();
        let mut facts = HashMap::new();
        for pid in descendants(root, parents) {
            let Some(task) = i32::try_from(pid)
                .ok()
                .and_then(|pid| info::<libc::proc_taskinfo>(pid, libc::PROC_PIDTASKINFO))
            else {
                continue;
            };
            facts.insert(
                pid,
                ProcessFacts {
                    parent: parent_of.get(&pid).copied().unwrap_or(0),
                    rss_bytes: task.pti_resident_size,
                    cpu_time: Duration::from_nanos(ticks_to_nanos(
                        task.pti_total_user.saturating_add(task.pti_total_system),
                    )),
                },
            );
        }
        // The root itself may be one this account cannot inspect.
        facts.entry(root).or_insert(ProcessFacts {
            parent: parent_of.get(&root).copied().unwrap_or(0),
            ..ProcessFacts::default()
        });
        sum_tree(root, &facts)
    }
}

#[cfg(windows)]
mod sys {
    use std::collections::HashMap;
    use std::time::Duration;

    use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    use super::{ProcessFacts, TreeUsage, descendants, sum_tree};

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

    fn filetime(time: FILETIME) -> Duration {
        let hundreds = (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        Duration::from_nanos(hundreds.saturating_mul(100))
    }

    fn open(pid: u32) -> Option<HANDLE> {
        // SAFETY: plain calls; the handle returned is closed by the caller.
        unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
        }
        .or_else(|_| unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
        .ok()
    }

    fn facts(pid: u32, parent: u32) -> Option<ProcessFacts> {
        let handle = open(pid)?;
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
        let cpu = if timed.is_ok() {
            filetime(kernel).saturating_add(filetime(user))
        } else {
            Duration::ZERO
        };
        // SAFETY: opened above, closed once.
        let _ = unsafe { CloseHandle(handle) };
        Some(ProcessFacts {
            parent,
            rss_bytes: rss,
            cpu_time: cpu,
        })
    }

    pub(super) fn sample_tree(root: u32) -> Option<TreeUsage> {
        let parents = parents();
        if !parents.iter().any(|(pid, _)| *pid == root) {
            return None;
        }
        let parent_of: HashMap<u32, u32> = parents.iter().copied().collect();
        let mut found = HashMap::new();
        for pid in descendants(root, parents) {
            let parent = parent_of.get(&pid).copied().unwrap_or(0);
            if let Some(fact) = facts(pid, parent) {
                found.insert(pid, fact);
            }
        }
        found.entry(root).or_insert(ProcessFacts {
            parent: parent_of.get(&root).copied().unwrap_or(0),
            ..ProcessFacts::default()
        });
        sum_tree(root, &found)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod sys {
    use super::TreeUsage;

    pub(super) const fn sample_tree(_: u32) -> Option<TreeUsage> {
        None
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
        let fact = |parent, rss, secs| ProcessFacts {
            parent,
            rss_bytes: rss,
            cpu_time: Duration::from_secs(secs),
        };
        let facts = HashMap::from([
            (1, fact(0, 1, 1)),
            (10, fact(1, 100, 10)),
            (11, fact(10, 20, 2)),
            (12, fact(11, 30, 3)),
            (20, fact(1, 999, 99)),
            // A recycled PID that names a descendant as its parent.
            (30, fact(12, 5, 1)),
        ]);
        assert_eq!(
            sum_tree(10, &facts),
            Some(TreeUsage {
                rss_bytes: 155,
                cpu_time: Duration::from_secs(16),
                processes: 4,
            })
        );
        assert_eq!(sum_tree(99, &facts), None);
        let cycle = descendants(1, [(1, 2), (2, 1), (3, 2)]);
        assert_eq!(cycle, vec![1, 2, 3]);
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
