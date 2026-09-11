// owner: b1-local-model-corpus
//
//! Stable case identifiers and fingerprints.
//!
//! `03-coverage-model.md`: "Case identifiers are stable (`local-0001`,
//! `wsl-0001`, and so on)." An identifier is assigned by position in the
//! deterministic generation order and pinned by the checked-in inventory, so a
//! change that renumbers cases is a visible diff of that file rather than a
//! silent shift. The fingerprint beside it is a hash of the case's rendered
//! steps: an identifier that keeps its number while its content changes is the
//! other way a replay instruction could go stale, and the fingerprint catches
//! that.

use std::fmt;

/// The prefix every local chain case carries.
pub const LOCAL_PREFIX: &str = "local-";

/// The environment variable a developer sets to one identifier to replay a
/// single case. It selects; it never regenerates, reorders or shrinks the
/// corpus, and the default run ignores nothing.
pub const SELECT_VARIABLE: &str = "CLI_CHAINS_CASE";

/// `local-NNNN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CaseId(pub u16);

impl CaseId {
    /// Reads `local-NNNN`, exactly four digits, from 0001.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.strip_prefix(LOCAL_PREFIX)?;
        if digits.len() != 4 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let number: u16 = digits.parse().ok()?;
        (number > 0).then_some(Self(number))
    }
}

impl fmt::Display for CaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{LOCAL_PREFIX}{:04}", self.0)
    }
}

/// 64-bit FNV-1a: small, dependency-free, and identical on every platform,
/// which is all a content fingerprint in a checked-in file needs.
#[must_use]
pub fn fingerprint(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
