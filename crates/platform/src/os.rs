// owner: d1-platform-core

//! Host operating system and architecture, and their standing in GitHub's
//! documented self-hosted runner support matrix.
//!
//! The matrix is quoted in `01-current-architecture.md` from GitHub's
//! self-hosted runner reference:
//!
//! > GitHub documents Windows 10/11 64-bit and Windows Server 2016/2019/2022
//! > 64-bit, macOS 11.0 (Big Sur) or later, and nine Linux distributions
//! > (RHEL/CentOS/Oracle 8+, Fedora 29+, Debian 10+, Ubuntu 20.04+, Mint 20+,
//! > openSUSE 15.2+, SLES 15 SP2+) as supported runner platforms. Supported
//! > architectures are x64 on all three, ARM64 on all three (**public
//! > preview**), and ARM32 on Linux only.
//!
//! Two consequences of that quotation shape this module, and both are
//! requirements rather than conveniences:
//!
//! 1. **ARM64 warns; it does not reject.** The persona's host is an Apple
//!    Silicon Mac mini, so a design that rejected public-preview architectures
//!    would reject the primary target machine. [`validate`] therefore returns
//!    `Ok` carrying a [`SupportWarning`].
//! 2. **Container actions and service containers require Linux.** A host does
//!    not gain them by running Docker (`01-current-architecture.md`, edge case
//!    2), so [`HostSupport::container_support`] reports the limitation and
//!    `f2` surfaces it on macOS and Windows policy validation.
//!
//! ## Why the classifier is a `match` and not a table lookup
//!
//! [`validate`] classifies with an exhaustive `match` over `(HostOs, HostArch)`
//! rather than by searching a list of accepted pairs. That costs a few lines
//! and buys two things. Adding a variant to either enum becomes a compile
//! error here — the pair cannot be silently accepted or silently rejected by
//! falling off the end of a table. And the tests can then carry their own,
//! independently written copy of the documented matrix; asserting a table
//! against itself would prove nothing.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The operating systems this product targets.
///
/// Deliberately not the same type as the domain's persisted `Os`: this crate
/// sits below the domain in the dependency graph for everything except its own
/// `runner-manager-domain` edge, and host detection must not wait on the
/// persistence model. Bridging the two is a caller's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostOs {
    /// Windows 10/11 and Windows Server 2016/2019/2022, 64-bit.
    Windows,
    /// macOS 11.0 (Big Sur) or later.
    MacOs,
    /// One of the nine documented Linux distributions.
    Linux,
}

/// The architectures GitHub documents for self-hosted runners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostArch {
    /// 64-bit x86. Generally available on all three operating systems.
    X64,
    /// 64-bit ARM. **Public preview** on all three operating systems.
    Arm64,
    /// 32-bit ARM. Documented on Linux only.
    Arm32,
}

impl HostOs {
    /// The canonical lowercase name, as GitHub's documentation writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::Linux => "linux",
        }
    }

    /// The operating system this binary was compiled for, or `None` when that
    /// is not one of the three documented systems.
    ///
    /// Resolved from `cfg!`, not from a runtime probe: a binary compiled for
    /// one operating system cannot be running on another, and a compile-time
    /// answer cannot be wrong about the thing it is most likely to be asked
    /// during an incident.
    #[must_use]
    pub const fn detect() -> Option<Self> {
        if cfg!(target_os = "windows") {
            Some(Self::Windows)
        } else if cfg!(target_os = "macos") {
            Some(Self::MacOs)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

impl fmt::Display for HostOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl HostArch {
    /// The canonical lowercase name, as GitHub's documentation writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
            Self::Arm32 => "arm32",
        }
    }

    /// The architecture this binary was compiled for, or `None` when that is
    /// not one of the three documented architectures.
    #[must_use]
    pub const fn detect() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::X64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Arm64)
        } else if cfg!(target_arch = "arm") {
            Some(Self::Arm32)
        } else {
            None
        }
    }
}

impl fmt::Display for HostArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An operating system and architecture pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Host {
    /// The host operating system.
    pub os: HostOs,
    /// The host architecture.
    pub arch: HostArch,
}

impl Host {
    /// Builds a pair without consulting the running machine.
    #[must_use]
    pub const fn new(os: HostOs, arch: HostArch) -> Self {
        Self { os, arch }
    }

    /// The pair this binary was compiled for.
    ///
    /// # Errors
    ///
    /// [`UnsupportedHost::UndocumentedPlatform`] when the operating system or
    /// the architecture is outside GitHub's documented matrix entirely — a
    /// FreeBSD or RISC-V build, for instance. That is a *build* that should
    /// not exist rather than a host that should be warned about, so it is an
    /// error and not a warning.
    pub const fn detect() -> Result<Self, UnsupportedHost> {
        match (HostOs::detect(), HostArch::detect()) {
            (Some(os), Some(arch)) => Ok(Self { os, arch }),
            _ => Err(UnsupportedHost::UndocumentedPlatform {
                os: std::env::consts::OS,
                arch: std::env::consts::ARCH,
            }),
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.arch)
    }
}

/// A host that GitHub's matrix does not document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UnsupportedHost {
    /// The build targets an operating system or architecture outside the
    /// matrix altogether.
    #[error(
        "runner-manager is built for Windows, macOS, and Linux on x64, ARM64, or ARM32, \
         but this binary targets {os}/{arch}, which GitHub does not document as a \
         self-hosted runner platform"
    )]
    UndocumentedPlatform {
        /// `std::env::consts::OS` for the offending build.
        os: &'static str,
        /// `std::env::consts::ARCH` for the offending build.
        arch: &'static str,
    },

    /// Both halves are documented, but not together: ARM32 is Linux-only.
    #[error(
        "GitHub documents ARM32 self-hosted runners on Linux only, so {os}/{arch} is not a \
         supported combination; use an x64 or ARM64 build of {os} instead"
    )]
    UndocumentedPair {
        /// The host operating system.
        os: HostOs,
        /// The host architecture.
        arch: HostArch,
    },
}

/// How firmly GitHub supports a documented pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStatus {
    /// Documented without qualification.
    GenerallyAvailable,
    /// Documented as public preview. Accepted, with a warning.
    PublicPreview,
}

/// Something an operator should be told about an accepted host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportWarning {
    /// ARM64 self-hosted runners are a GitHub public preview.
    Arm64PublicPreview,
}

impl SupportWarning {
    /// Operator-facing text. Actionable rather than merely descriptive: it says
    /// what the operator may observe, not just that a label applies.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Arm64PublicPreview => {
                "ARM64 self-hosted runners are a GitHub public preview. Runners will \
                 register and run jobs, but GitHub may change or withdraw ARM64 support \
                 without the notice a generally available platform gets, and some actions \
                 publish no ARM64 build."
            }
        }
    }
}

impl fmt::Display for SupportWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

/// Whether this host can run container actions and service containers.
///
/// `01-current-architecture.md`, edge case 2: a host does not gain them merely
/// because Docker is installed; GitHub's reference requires Linux.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerSupport {
    /// Container actions and service containers are available.
    Available,
    /// They are unavailable on this operating system, whatever is installed.
    RequiresLinux,
}

impl ContainerSupport {
    /// Whether container workflow features work on this host.
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }

    /// Operator-facing text for the limitation, or `None` when there is none.
    #[must_use]
    pub const fn message(self) -> Option<&'static str> {
        match self {
            Self::Available => None,
            Self::RequiresLinux => Some(
                "Container actions and service containers require a Linux runner. This host \
                 cannot run them even with Docker installed, so a workflow that uses \
                 `container:` or `services:` will fail on it.",
            ),
        }
    }
}

/// One documented operating system release, with the oldest version GitHub
/// documents for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentedRelease {
    /// The release or distribution name, as GitHub's documentation writes it.
    pub name: &'static str,
    /// The oldest documented version, or `None` when GitHub names the release
    /// without a version floor.
    pub minimum_version: Option<&'static str>,
}

impl fmt::Display for DocumentedRelease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.minimum_version {
            Some(version) => write!(f, "{} {version}+", self.name),
            None => f.write_str(self.name),
        }
    }
}

const fn release(name: &'static str, minimum_version: Option<&'static str>) -> DocumentedRelease {
    DocumentedRelease {
        name,
        minimum_version,
    }
}

const WINDOWS_RELEASES: &[DocumentedRelease] = &[
    release("Windows 10", None),
    release("Windows 11", None),
    release("Windows Server 2016", None),
    release("Windows Server 2019", None),
    release("Windows Server 2022", None),
];

const MACOS_RELEASES: &[DocumentedRelease] = &[release("macOS", Some("11.0"))];

/// The nine distributions `01-current-architecture.md` lists. RHEL, CentOS and
/// Oracle share one "8+" floor in GitHub's documentation but are three
/// separate distributions, which is how the count reaches nine.
const LINUX_RELEASES: &[DocumentedRelease] = &[
    release("Red Hat Enterprise Linux", Some("8")),
    release("CentOS", Some("8")),
    release("Oracle Linux", Some("8")),
    release("Fedora", Some("29")),
    release("Debian", Some("10")),
    release("Ubuntu", Some("20.04")),
    release("Linux Mint", Some("20")),
    release("openSUSE", Some("15.2")),
    release("SUSE Linux Enterprise Server", Some("15 SP2")),
];

/// The releases GitHub documents for one operating system.
///
/// Exposed as data so `f2` can render the list an operator is measured against
/// without restating it, and so a future correction to the matrix lands in one
/// place.
#[must_use]
pub const fn documented_releases(os: HostOs) -> &'static [DocumentedRelease] {
    match os {
        HostOs::Windows => WINDOWS_RELEASES,
        HostOs::MacOs => MACOS_RELEASES,
        HostOs::Linux => LINUX_RELEASES,
    }
}

/// The verdict on one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSupport {
    host: Host,
    status: SupportStatus,
    warnings: Vec<SupportWarning>,
    container_support: ContainerSupport,
}

impl HostSupport {
    /// The pair this verdict is about.
    #[must_use]
    pub const fn host(&self) -> Host {
        self.host
    }

    /// Whether GitHub documents the pair without qualification.
    #[must_use]
    pub const fn status(&self) -> SupportStatus {
        self.status
    }

    /// Everything an operator should be told. Empty for a generally available
    /// pair.
    #[must_use]
    pub fn warnings(&self) -> &[SupportWarning] {
        &self.warnings
    }

    /// Whether container actions and service containers work here.
    #[must_use]
    pub const fn container_support(&self) -> ContainerSupport {
        self.container_support
    }

    /// The releases GitHub documents for this host's operating system.
    #[must_use]
    pub const fn documented_releases(&self) -> &'static [DocumentedRelease] {
        documented_releases(self.host.os)
    }
}

/// Classifies a host against GitHub's documented matrix.
///
/// # Errors
///
/// [`UnsupportedHost::UndocumentedPair`] when both halves are documented but
/// not together, which today means ARM32 anywhere other than Linux.
pub fn validate(host: Host) -> Result<HostSupport, UnsupportedHost> {
    // Exhaustive on purpose: see the module documentation. A new `HostOs` or
    // `HostArch` variant must fail to compile here rather than fall through to
    // an accept or a reject nobody chose.
    let status = match (host.os, host.arch) {
        (HostOs::Windows | HostOs::MacOs | HostOs::Linux, HostArch::X64)
        | (HostOs::Linux, HostArch::Arm32) => SupportStatus::GenerallyAvailable,

        (HostOs::Windows | HostOs::MacOs | HostOs::Linux, HostArch::Arm64) => {
            SupportStatus::PublicPreview
        }

        (HostOs::Windows | HostOs::MacOs, HostArch::Arm32) => {
            return Err(UnsupportedHost::UndocumentedPair {
                os: host.os,
                arch: host.arch,
            });
        }
    };

    let warnings = match status {
        SupportStatus::GenerallyAvailable => Vec::new(),
        SupportStatus::PublicPreview => vec![SupportWarning::Arm64PublicPreview],
    };

    let container_support = match host.os {
        HostOs::Linux => ContainerSupport::Available,
        HostOs::Windows | HostOs::MacOs => ContainerSupport::RequiresLinux,
    };

    Ok(HostSupport {
        host,
        status,
        warnings,
        container_support,
    })
}

/// Classifies the host this binary is running on.
///
/// # Errors
///
/// Both variants of [`UnsupportedHost`]; see [`Host::detect`] and [`validate`].
pub fn detect() -> Result<HostSupport, UnsupportedHost> {
    validate(Host::detect()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The matrix, written out here from the evidence line in
    /// `01-current-architecture.md` rather than read back from the module under
    /// test. Asserting the classifier against its own table would prove
    /// nothing; this list is the independent copy that makes the assertions
    /// mean something.
    const DOCUMENTED: &[(HostOs, HostArch)] = &[
        (HostOs::Windows, HostArch::X64),
        (HostOs::MacOs, HostArch::X64),
        (HostOs::Linux, HostArch::X64),
        (HostOs::Windows, HostArch::Arm64),
        (HostOs::MacOs, HostArch::Arm64),
        (HostOs::Linux, HostArch::Arm64),
        (HostOs::Linux, HostArch::Arm32),
    ];

    const UNDOCUMENTED: &[(HostOs, HostArch)] = &[
        (HostOs::Windows, HostArch::Arm32),
        (HostOs::MacOs, HostArch::Arm32),
    ];

    const ALL_OS: &[HostOs] = &[HostOs::Windows, HostOs::MacOs, HostOs::Linux];
    const ALL_ARCH: &[HostArch] = &[HostArch::X64, HostArch::Arm64, HostArch::Arm32];

    /// The DoD clause "accepts every documented pair, rejects an undocumented
    /// pair", expressed once so that it can be pointed at a deliberately broken
    /// classifier as well as at the real one.
    ///
    /// Returns `Err` with the first disagreement rather than panicking, which
    /// is what lets `the_matrix_assertions_catch_a_classifier_that_accepts_everything`
    /// below prove these assertions are not vacuous.
    fn check_matrix(
        classify: impl Fn(Host) -> Result<HostSupport, UnsupportedHost>,
    ) -> Result<(), String> {
        for &(os, arch) in DOCUMENTED {
            if classify(Host::new(os, arch)).is_err() {
                return Err(format!("{os}/{arch} is documented but was rejected"));
            }
        }
        for &(os, arch) in UNDOCUMENTED {
            if classify(Host::new(os, arch)).is_ok() {
                return Err(format!("{os}/{arch} is undocumented but was accepted"));
            }
        }
        Ok(())
    }

    #[test]
    fn documented_pairs_are_accepted_and_undocumented_pairs_are_rejected() {
        check_matrix(validate).expect("the documented matrix must classify exactly");
    }

    #[test]
    fn the_matrix_assertions_catch_a_classifier_that_accepts_everything() {
        // The violation the DoD cares about is a matrix that has quietly become
        // permissive. If `check_matrix` cannot see that, the test above is
        // decoration, so point it at a classifier that is wrong in exactly that
        // way and require it to complain.
        let permissive = |host: Host| {
            Ok(HostSupport {
                host,
                status: SupportStatus::GenerallyAvailable,
                warnings: Vec::new(),
                container_support: ContainerSupport::Available,
            })
        };

        let complaint =
            check_matrix(permissive).expect_err("a permissive classifier must be caught");
        assert!(
            complaint.contains("undocumented but was accepted"),
            "the complaint must name the failure mode, got: {complaint}"
        );
    }

    #[test]
    fn the_matrix_assertions_catch_a_classifier_that_rejects_everything() {
        let hostile = |host: Host| {
            Err(UnsupportedHost::UndocumentedPair {
                os: host.os,
                arch: host.arch,
            })
        };

        let complaint = check_matrix(hostile).expect_err("a hostile classifier must be caught");
        assert!(
            complaint.contains("documented but was rejected"),
            "the complaint must name the failure mode, got: {complaint}"
        );
    }

    #[test]
    fn every_pair_is_classified_and_the_two_sets_do_not_overlap() {
        // Guards against a pair being forgotten by both lists above as the
        // matrix changes: the cross product must be partitioned exactly.
        let mut seen = Vec::new();
        for &os in ALL_OS {
            for &arch in ALL_ARCH {
                let pair = (os, arch);
                let documented = DOCUMENTED.contains(&pair);
                let undocumented = UNDOCUMENTED.contains(&pair);
                assert!(
                    documented ^ undocumented,
                    "{os}/{arch} must appear in exactly one of the two test tables"
                );
                seen.push(pair);
            }
        }
        assert_eq!(seen.len(), DOCUMENTED.len() + UNDOCUMENTED.len());
    }

    #[test]
    fn arm64_is_accepted_with_a_public_preview_warning_on_all_three_systems() {
        for &os in ALL_OS {
            let support = validate(Host::new(os, HostArch::Arm64))
                .expect("ARM64 must be accepted, not rejected: the persona's host is ARM64");

            assert_eq!(support.status(), SupportStatus::PublicPreview, "on {os}");
            assert_eq!(
                support.warnings(),
                [SupportWarning::Arm64PublicPreview],
                "on {os}"
            );
            assert!(
                support.warnings()[0].message().contains("public preview"),
                "the warning must say what it is warning about"
            );
        }
    }

    #[test]
    fn generally_available_pairs_carry_no_warning() {
        for &(os, arch) in DOCUMENTED {
            if arch == HostArch::Arm64 {
                continue;
            }
            let support = validate(Host::new(os, arch)).expect("documented");
            assert_eq!(support.status(), SupportStatus::GenerallyAvailable);
            assert!(
                support.warnings().is_empty(),
                "{os}/{arch} is generally available and must not warn"
            );
        }
    }

    #[test]
    fn container_actions_are_reported_as_linux_only() {
        let linux = validate(Host::new(HostOs::Linux, HostArch::X64)).expect("documented");
        assert_eq!(linux.container_support(), ContainerSupport::Available);
        assert!(linux.container_support().is_available());
        assert!(linux.container_support().message().is_none());

        for &os in &[HostOs::Windows, HostOs::MacOs] {
            let support = validate(Host::new(os, HostArch::X64)).expect("documented");
            assert_eq!(
                support.container_support(),
                ContainerSupport::RequiresLinux,
                "{os} must report the container limitation so f2 can surface it"
            );
            assert!(!support.container_support().is_available());

            let message = support
                .container_support()
                .message()
                .expect("the limitation must carry operator-facing text");
            // Edge case 2's whole point is that Docker does not lift it, so the
            // message must say so or an operator will install Docker and retry.
            assert!(message.contains("Docker"), "on {os}: {message}");
            assert!(message.contains("Linux"), "on {os}: {message}");
        }
    }

    #[test]
    fn an_undocumented_pair_says_which_pair_and_why() {
        let error = validate(Host::new(HostOs::Windows, HostArch::Arm32))
            .expect_err("ARM32 is documented on Linux only");

        assert_eq!(
            error,
            UnsupportedHost::UndocumentedPair {
                os: HostOs::Windows,
                arch: HostArch::Arm32,
            }
        );

        let rendered = error.to_string();
        assert!(rendered.contains("windows"), "{rendered}");
        assert!(rendered.contains("arm32"), "{rendered}");
        assert!(rendered.contains("Linux only"), "{rendered}");
    }

    #[test]
    fn the_documented_release_lists_match_the_evidence_line() {
        // Five Windows releases, macOS with an 11.0 floor, and nine Linux
        // distributions. The counts are asserted because a distribution
        // dropped by an edit is otherwise invisible.
        assert_eq!(documented_releases(HostOs::Windows).len(), 5);
        assert_eq!(documented_releases(HostOs::MacOs).len(), 1);
        assert_eq!(
            documented_releases(HostOs::Linux).len(),
            9,
            "`01-current-architecture.md` names nine Linux distributions"
        );

        assert_eq!(
            documented_releases(HostOs::MacOs)[0].minimum_version,
            Some("11.0"),
            "macOS 11.0 (Big Sur) is the documented floor"
        );
        assert_eq!(
            documented_releases(HostOs::MacOs)[0].to_string(),
            "macOS 11.0+"
        );

        for release in documented_releases(HostOs::Windows) {
            assert!(
                release.name.starts_with("Windows"),
                "unexpected Windows release: {release}"
            );
        }

        let linux: Vec<String> = documented_releases(HostOs::Linux)
            .iter()
            .map(ToString::to_string)
            .collect();
        for expected in [
            "Red Hat Enterprise Linux 8+",
            "CentOS 8+",
            "Oracle Linux 8+",
            "Fedora 29+",
            "Debian 10+",
            "Ubuntu 20.04+",
            "Linux Mint 20+",
            "openSUSE 15.2+",
            "SUSE Linux Enterprise Server 15 SP2+",
        ] {
            assert!(
                linux.iter().any(|found| found == expected),
                "missing documented distribution {expected}; found {linux:?}"
            );
        }
    }

    /// Runs natively on each leg of the CI matrix, which is the only place the
    /// three answers can actually differ.
    #[test]
    fn this_host_is_a_documented_pair() {
        let support = detect().expect("every CI leg and every supported host must classify");

        assert_eq!(
            support.host(),
            Host::detect().expect("detection agrees with itself")
        );
        assert!(
            DOCUMENTED.contains(&(support.host().os, support.host().arch)),
            "detected {} is not in the documented matrix",
            support.host()
        );

        // The macOS CI leg is Apple Silicon by design (`ci.yml` asserts
        // `uname -m` is arm64), so on that leg this is the public-preview path
        // running for real rather than as a constructed pair.
        if support.host().arch == HostArch::Arm64 {
            assert_eq!(support.status(), SupportStatus::PublicPreview);
            assert!(!support.warnings().is_empty());
        }
    }

    #[test]
    fn display_and_serde_round_trip_the_canonical_names() {
        assert_eq!(
            Host::new(HostOs::Windows, HostArch::X64).to_string(),
            "windows/x64"
        );
        assert_eq!(
            Host::new(HostOs::MacOs, HostArch::Arm64).to_string(),
            "macos/arm64"
        );
        assert_eq!(
            Host::new(HostOs::Linux, HostArch::Arm32).to_string(),
            "linux/arm32"
        );

        for &os in ALL_OS {
            for &arch in ALL_ARCH {
                let host = Host::new(os, arch);
                let json = serde_json::to_string(&host).expect("serialisable");
                let back: Host = serde_json::from_str(&json).expect("deserialisable");
                assert_eq!(host, back, "{json}");
            }
        }
    }
}
