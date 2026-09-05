// owner: d1-platform-core

//! Where this host stands in GitHub's documented self-hosted runner support
//! matrix.
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
//! # The types are the domain's; the verdict is this module's
//!
//! [`Os`] and [`Arch`] come from `runner-manager-domain` and are not restated
//! here. An earlier version of this module defined its own `HostOs`/`HostArch`
//! on the reasoning that platform detection sits below the persistence model —
//! but this crate already depends on `runner-manager-domain`, so nothing was
//! being avoided, and two enums naming the same three values had begun to
//! disagree: `arm32` against the domain's `arm`, `windows`/`macos` against
//! `win`/`osx`. One of those spellings feeds runner-package selection, so a
//! disagreement there is a download of the wrong archive rather than a
//! cosmetic difference. The domain's own documentation says as much —
//! *"Enforcing that pairing is `d1`'s job; this enum only has to be able to
//! name the values"* — which asks `d1` to **validate** those types, not to mint
//! parallel ones.
//!
//! For the same reason the two predicates the domain already answers are not
//! answered again here. [`SupportStatus`] and the ARM64 warning are derived
//! from [`Arch::is_public_preview`], and [`ContainerSupport`] from
//! [`Os::supports_container_actions`], so `f2` reading either this module or
//! the domain gets the same verdict by construction rather than by two tables
//! being kept in step.
//!
//! What is left is genuinely this module's: which *pairs* are documented,
//! detection of the running host, the operator-facing text, and
//! [`documented_releases`].
//!
//! ## Why the pair check is a `match` and not a table lookup
//!
//! [`validate`] classifies with an exhaustive `match` over `(Os, Arch)` rather
//! than by searching a list of accepted pairs. That costs a few lines and buys
//! two things. Adding a variant to either enum becomes a compile error here —
//! the pair cannot be silently accepted or silently rejected by falling off the
//! end of a table. And the tests can then carry their own, independently
//! written copy of the documented matrix; asserting a table against itself
//! would prove nothing.

use std::fmt;

use runner_manager_domain::model::{Arch, Os};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Prose names
//
// `Os::label_token` and `Arch::label_token` are GitHub's runner-package tokens
// — `win`, `osx`, `arm` — and `e2` selects a download with them. They are not
// prose, and an operator reading "GitHub documents ARM32 runners on win only"
// is being shown an internal token. These two functions exist for messages and
// for nothing else; nothing that builds a label, a package name, or a path may
// use them.
// ---------------------------------------------------------------------------

/// The operating system's name as GitHub's documentation writes it in prose.
#[must_use]
pub const fn os_name(os: Os) -> &'static str {
    match os {
        Os::Windows => "Windows",
        Os::MacOs => "macOS",
        Os::Linux => "Linux",
    }
}

/// The architecture's name as GitHub's documentation writes it in prose.
#[must_use]
pub const fn arch_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "x64",
        Arch::Arm64 => "ARM64",
        Arch::Arm32 => "ARM32",
    }
}

/// The operating system this binary was compiled for, or `None` when that is
/// not one of the three documented systems.
///
/// Resolved from `cfg!`, not from a runtime probe: a binary compiled for one
/// operating system cannot be running on another, and a compile-time answer
/// cannot be wrong about the thing it is most likely to be asked during an
/// incident.
#[must_use]
pub const fn detect_os() -> Option<Os> {
    if cfg!(target_os = "windows") {
        Some(Os::Windows)
    } else if cfg!(target_os = "macos") {
        Some(Os::MacOs)
    } else if cfg!(target_os = "linux") {
        Some(Os::Linux)
    } else {
        None
    }
}

/// The architecture this binary was compiled for, or `None` when that is not
/// one of the three documented architectures.
#[must_use]
pub const fn detect_arch() -> Option<Arch> {
    if cfg!(target_arch = "x86_64") {
        Some(Arch::X64)
    } else if cfg!(target_arch = "aarch64") {
        Some(Arch::Arm64)
    } else if cfg!(target_arch = "arm") {
        Some(Arch::Arm32)
    } else {
        None
    }
}

/// The operating system and architecture this binary was compiled for.
///
/// # Errors
///
/// [`UnsupportedHost::UndocumentedPlatform`] when the operating system or the
/// architecture is outside GitHub's documented matrix entirely — a FreeBSD or
/// RISC-V build, for instance. That is a *build* that should not exist rather
/// than a host that should be warned about, so it is an error and not a
/// warning.
pub const fn detect_host() -> Result<(Os, Arch), UnsupportedHost> {
    match (detect_os(), detect_arch()) {
        (Some(os), Some(arch)) => Ok((os, arch)),
        _ => Err(UnsupportedHost::UndocumentedPlatform {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        }),
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
        "GitHub documents ARM32 self-hosted runners on Linux only, so {} on {} is not a \
         supported combination; use an x64 or ARM64 build of {} instead",
        arch_name(*arch),
        os_name(*os),
        os_name(*os)
    )]
    UndocumentedPair {
        /// The host operating system.
        os: Os,
        /// The host architecture.
        arch: Arch,
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

impl SupportStatus {
    /// Derived from [`Arch::is_public_preview`] rather than decided again here,
    /// so `f2` cannot get one answer from the domain and another from this
    /// module.
    #[must_use]
    pub const fn of(arch: Arch) -> Self {
        if arch.is_public_preview() {
            Self::PublicPreview
        } else {
            Self::GenerallyAvailable
        }
    }
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
    /// Derived from [`Os::supports_container_actions`]. This type adds the
    /// operator-facing explanation; it does not re-decide the question.
    #[must_use]
    pub const fn of(os: Os) -> Self {
        if os.supports_container_actions() {
            Self::Available
        } else {
            Self::RequiresLinux
        }
    }

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
pub const fn documented_releases(os: Os) -> &'static [DocumentedRelease] {
    match os {
        Os::Windows => WINDOWS_RELEASES,
        Os::MacOs => MACOS_RELEASES,
        Os::Linux => LINUX_RELEASES,
    }
}

/// The verdict on one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSupport {
    os: Os,
    arch: Arch,
    status: SupportStatus,
    warnings: Vec<SupportWarning>,
    container_support: ContainerSupport,
}

impl HostSupport {
    /// The operating system this verdict is about.
    #[must_use]
    pub const fn os(&self) -> Os {
        self.os
    }

    /// The architecture this verdict is about.
    #[must_use]
    pub const fn arch(&self) -> Arch {
        self.arch
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
        documented_releases(self.os)
    }
}

impl fmt::Display for HostSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}", arch_name(self.arch), os_name(self.os))
    }
}

/// Classifies a host against GitHub's documented matrix.
///
/// # Errors
///
/// [`UnsupportedHost::UndocumentedPair`] when both halves are documented but
/// not together, which today means ARM32 anywhere other than Linux.
pub fn validate(os: Os, arch: Arch) -> Result<HostSupport, UnsupportedHost> {
    // Exhaustive on purpose: see the module documentation. A new `Os` or `Arch`
    // variant must fail to compile here rather than fall through to an accept
    // or a reject nobody chose.
    //
    // This match decides *only* which pairs are documented, which is the part
    // the domain explicitly delegates. How firmly a documented pair is
    // supported, and whether it runs containers, are the domain's own
    // predicates and are read from there below.
    match (os, arch) {
        (Os::Windows | Os::MacOs | Os::Linux, Arch::X64 | Arch::Arm64)
        | (Os::Linux, Arch::Arm32) => {}

        (Os::Windows | Os::MacOs, Arch::Arm32) => {
            return Err(UnsupportedHost::UndocumentedPair { os, arch });
        }
    }

    let status = SupportStatus::of(arch);

    // Matched on `arch`, not on `status`. The *verdict* is single-sourced from
    // `Arch::is_public_preview` and stays that way -- `status` still gates the
    // arms -- but the warning *text* names an architecture, and choosing it by
    // status re-encoded which architecture that is. A second preview
    // architecture would have been handed ARM64's message with no compile
    // error: the one place this module's "adding a variant is a compile error"
    // claim did not hold.
    //
    // Matching the pair means a new `Arch` variant fails to compile here until
    // someone decides what it is owed, which for a preview architecture is a
    // `SupportWarning` variant of its own.
    let warnings = match (status, arch) {
        (SupportStatus::GenerallyAvailable, _) => Vec::new(),
        (SupportStatus::PublicPreview, Arch::Arm64) => vec![SupportWarning::Arm64PublicPreview],
        // Unreachable while ARM64 is the only preview architecture, and it is
        // `Arch::is_public_preview` that decides that, not this match.
        (SupportStatus::PublicPreview, Arch::X64 | Arch::Arm32) => Vec::new(),
    };

    Ok(HostSupport {
        os,
        arch,
        status,
        warnings,
        container_support: ContainerSupport::of(os),
    })
}

/// Classifies the host this binary is running on.
///
/// # Errors
///
/// Both variants of [`UnsupportedHost`]; see [`detect_host`] and [`validate`].
pub fn detect() -> Result<HostSupport, UnsupportedHost> {
    let (os, arch) = detect_host()?;
    validate(os, arch)
}

// ---------------------------------------------------------------------------
// Privacy consent
// ---------------------------------------------------------------------------

/// The macOS settings pane that grants a program Full Disk Access.
///
/// A URL rather than a scripted click: `x-apple.systempreferences:` is the
/// documented way to open one pane of System Settings, it needs no automation
/// permission of its own, and it lands the operator on the exact list they have
/// to add the program to.
///
/// It lives here rather than beside the command that opens it because it is an
/// operating-system constant, and this crate is where those are kept. Deciding
/// *whether* to open anything stays with the caller, which already has one
/// policy for that.
pub const FULL_DISK_ACCESS_SETTINGS_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";

#[cfg(test)]
mod tests {
    use super::*;

    /// The matrix, written out here from the evidence line in
    /// `01-current-architecture.md` rather than read back from the module under
    /// test. Asserting the classifier against its own table would prove
    /// nothing; this list is the independent copy that makes the assertions
    /// mean something.
    const DOCUMENTED: &[(Os, Arch)] = &[
        (Os::Windows, Arch::X64),
        (Os::MacOs, Arch::X64),
        (Os::Linux, Arch::X64),
        (Os::Windows, Arch::Arm64),
        (Os::MacOs, Arch::Arm64),
        (Os::Linux, Arch::Arm64),
        (Os::Linux, Arch::Arm32),
    ];

    const UNDOCUMENTED: &[(Os, Arch)] = &[(Os::Windows, Arch::Arm32), (Os::MacOs, Arch::Arm32)];

    /// The DoD clause "accepts every documented pair, rejects an undocumented
    /// pair", expressed once so that it can be pointed at a deliberately broken
    /// classifier as well as at the real one.
    ///
    /// Returns `Err` with the first disagreement rather than panicking, which
    /// is what lets `the_matrix_assertions_catch_a_classifier_that_accepts_everything`
    /// below prove these assertions are not vacuous.
    fn check_matrix(
        classify: impl Fn(Os, Arch) -> Result<HostSupport, UnsupportedHost>,
    ) -> Result<(), String> {
        for &(os, arch) in DOCUMENTED {
            if classify(os, arch).is_err() {
                return Err(format!(
                    "{}/{} is documented but was rejected",
                    os.label_token(),
                    arch.label_token()
                ));
            }
        }
        for &(os, arch) in UNDOCUMENTED {
            if classify(os, arch).is_ok() {
                return Err(format!(
                    "{}/{} is undocumented but was accepted",
                    os.label_token(),
                    arch.label_token()
                ));
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
        let permissive = |os, arch| {
            Ok(HostSupport {
                os,
                arch,
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
        let hostile = |os, arch| Err(UnsupportedHost::UndocumentedPair { os, arch });

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
        //
        // `Os::ALL` and `Arch::ALL` come from the domain, so a variant added
        // there is covered here without an edit — which was one of the reasons
        // for stopping keeping a second pair of enums in this file.
        let mut seen = Vec::new();
        for &os in &Os::ALL {
            for &arch in &Arch::ALL {
                let pair = (os, arch);
                let documented = DOCUMENTED.contains(&pair);
                let undocumented = UNDOCUMENTED.contains(&pair);
                assert!(
                    documented ^ undocumented,
                    "{}/{} must appear in exactly one of the two test tables",
                    os.label_token(),
                    arch.label_token()
                );
                seen.push(pair);
            }
        }
        assert_eq!(seen.len(), DOCUMENTED.len() + UNDOCUMENTED.len());
    }

    #[test]
    fn arm64_is_accepted_with_a_public_preview_warning_on_all_three_systems() {
        for &os in &Os::ALL {
            let support = validate(os, Arch::Arm64)
                .expect("ARM64 must be accepted, not rejected: the persona's host is ARM64");

            assert_eq!(
                support.status(),
                SupportStatus::PublicPreview,
                "on {}",
                os_name(os)
            );
            assert_eq!(
                support.warnings(),
                [SupportWarning::Arm64PublicPreview],
                "on {}",
                os_name(os)
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
            if arch == Arch::Arm64 {
                continue;
            }
            let support = validate(os, arch).expect("documented");
            assert_eq!(support.status(), SupportStatus::GenerallyAvailable);
            assert!(
                support.warnings().is_empty(),
                "{}/{} is generally available and must not warn",
                os.label_token(),
                arch.label_token()
            );
        }
    }

    #[test]
    fn container_actions_are_reported_as_linux_only() {
        let linux = validate(Os::Linux, Arch::X64).expect("documented");
        assert_eq!(linux.container_support(), ContainerSupport::Available);
        assert!(linux.container_support().is_available());
        assert!(linux.container_support().message().is_none());

        for os in [Os::Windows, Os::MacOs] {
            let support = validate(os, Arch::X64).expect("documented");
            assert_eq!(
                support.container_support(),
                ContainerSupport::RequiresLinux,
                "{} must report the container limitation so f2 can surface it",
                os_name(os)
            );
            assert!(!support.container_support().is_available());

            let message = support
                .container_support()
                .message()
                .expect("the limitation must carry operator-facing text");
            // Edge case 2's whole point is that Docker does not lift it, so the
            // message must say so or an operator will install Docker and retry.
            assert!(message.contains("Docker"), "on {}: {message}", os_name(os));
            assert!(message.contains("Linux"), "on {}: {message}", os_name(os));
        }
    }

    /// The single-source property the `HostOs`/`HostArch` deletion bought.
    ///
    /// `f2` may read the verdict from this module or from the domain predicate,
    /// and the two must agree for every host — not because both tables were
    /// updated together, but because there is only one table.
    #[test]
    fn the_verdicts_agree_with_the_domain_predicates_they_are_derived_from() {
        for &(os, arch) in DOCUMENTED {
            let support = validate(os, arch).expect("documented");

            assert_eq!(
                support.container_support().is_available(),
                os.supports_container_actions(),
                "container support disagrees with the domain for {}",
                os_name(os)
            );
            assert_eq!(
                support.status() == SupportStatus::PublicPreview,
                arch.is_public_preview(),
                "preview status disagrees with the domain for {}",
                arch_name(arch)
            );
            assert_eq!(
                support.warnings().is_empty(),
                !arch.is_public_preview(),
                "the warning list disagrees with the domain for {}",
                arch_name(arch)
            );
        }
    }

    /// Prose names and routing tokens are different things, deliberately.
    ///
    /// The trap this guards is an edit that reaches for `label_token()` in an
    /// operator-facing message, which would render "GitHub documents ARM32
    /// runners on win only". The tokens belong to runner-package selection and
    /// nowhere else.
    #[test]
    fn prose_names_are_not_routing_tokens() {
        assert_eq!(os_name(Os::Windows), "Windows");
        assert_eq!(Os::Windows.label_token(), "win");
        assert_eq!(os_name(Os::MacOs), "macOS");
        assert_eq!(Os::MacOs.label_token(), "osx");
        assert_eq!(arch_name(Arch::Arm32), "ARM32");
        assert_eq!(Arch::Arm32.label_token(), "arm");

        // Linux and x64 are spelled the same either way, which is exactly why
        // the other four are worth pinning: a partial overlap is what let two
        // spellings drift without anything failing.
        assert_eq!(os_name(Os::Linux), "Linux");
        assert_eq!(arch_name(Arch::X64), "x64");
    }

    #[test]
    fn an_undocumented_pair_says_which_pair_and_why() {
        let error =
            validate(Os::Windows, Arch::Arm32).expect_err("ARM32 is documented on Linux only");

        assert_eq!(
            error,
            UnsupportedHost::UndocumentedPair {
                os: Os::Windows,
                arch: Arch::Arm32,
            }
        );

        // Prose, not tokens: an operator should not have to know that `win`
        // means Windows.
        let rendered = error.to_string();
        assert!(rendered.contains("Windows"), "{rendered}");
        assert!(rendered.contains("ARM32"), "{rendered}");
        assert!(rendered.contains("Linux only"), "{rendered}");
    }

    #[test]
    fn the_documented_release_lists_match_the_evidence_line() {
        // Five Windows releases, macOS with an 11.0 floor, and nine Linux
        // distributions. The counts are asserted because a distribution
        // dropped by an edit is otherwise invisible.
        assert_eq!(documented_releases(Os::Windows).len(), 5);
        assert_eq!(documented_releases(Os::MacOs).len(), 1);
        assert_eq!(
            documented_releases(Os::Linux).len(),
            9,
            "`01-current-architecture.md` names nine Linux distributions"
        );

        assert_eq!(
            documented_releases(Os::MacOs)[0].minimum_version,
            Some("11.0"),
            "macOS 11.0 (Big Sur) is the documented floor"
        );
        assert_eq!(documented_releases(Os::MacOs)[0].to_string(), "macOS 11.0+");

        for release in documented_releases(Os::Windows) {
            assert!(
                release.name.starts_with("Windows"),
                "unexpected Windows release: {release}"
            );
        }

        let linux: Vec<String> = documented_releases(Os::Linux)
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
            (support.os(), support.arch()),
            detect_host().expect("detection agrees with itself")
        );
        assert!(
            DOCUMENTED.contains(&(support.os(), support.arch())),
            "detected {support} is not in the documented matrix"
        );

        // The macOS CI leg is Apple Silicon by design (`ci.yml` asserts
        // `uname -m` is arm64), so on that leg this is the public-preview path
        // running for real rather than as a constructed pair.
        if support.arch() == Arch::Arm64 {
            assert_eq!(support.status(), SupportStatus::PublicPreview);
            assert!(!support.warnings().is_empty());
        }
    }

    /// A host built from this module's answer is a host the domain accepts.
    ///
    /// The `HostOs`/`HostArch` version could not state this at all: the caller
    /// had to bridge between two enums, and `platform::os::Host` even
    /// serialised its architecture under a different field name (`arch`) than
    /// the domain's `Host` (`architecture`). There is now nothing to bridge.
    #[test]
    fn a_detected_host_feeds_the_domain_directly() {
        use std::num::NonZeroU16;

        use runner_manager_domain::model::{Host, HostId};

        let support = detect().expect("this host classifies");
        let host = Host::new(
            HostId::from_u128(1),
            "the machine this test is running on",
            support.os(),
            support.arch(),
            NonZeroU16::new(4).expect("non-zero"),
            chrono::Utc::now(),
        )
        .expect("a named host is valid");

        assert_eq!(host.os, support.os());
        assert_eq!(host.architecture, support.arch());
    }
}
