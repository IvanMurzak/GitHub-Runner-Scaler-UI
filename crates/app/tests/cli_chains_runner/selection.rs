// owner: b2-local-chain-runner
//
//! Which cases the default run executes, and how one case is selected for
//! local diagnosis.
//!
//! # The default run cannot be narrowed
//!
//! [`default_selection`] takes no input at all: it is a function of the
//! checked-in corpus alone. The case selector, [`SELECT_VARIABLE`], is read by
//! [`selected_case`] and by nothing on the default path, and the one test that
//! calls it is `#[ignore]`d, so `cargo nextest run --workspace` never executes
//! it and an exported variable cannot turn the full run into a one-case run. `02-target-architecture.md`: "A single-case filter/environment
//! input may select a case for local replay, but cannot change the default CI
//! corpus."
//!
//! # Why the curated journeys
//!
//! Task b2 asks for representative success and refusal journeys across host,
//! repository, organization, workspace, status, and authentication setup and
//! teardown; task b3 wires the whole inventory. The curated journeys are the
//! hand-written, named chains the corpus opens with -- each written for an
//! invariant, a cross-scope interaction or a recovery path -- so they are the
//! representative set by construction rather than by a list somebody has to
//! keep in step with the inventory. [`AREAS`] is what makes "representative"
//! checkable: every area must be reached by a successful and, where the
//! surface can refuse, a refused action.

use std::env::VarError;

use crate::cli_chains::action::{Action, ActionKind};
use crate::cli_chains::corpus::{self, Case, Origin};
use crate::cli_chains::coverage::Entry;
use crate::cli_chains::ids::{CaseId, SELECT_VARIABLE};

/// Every case the default run executes, in inventory order.
#[must_use]
pub fn default_selection() -> Vec<&'static Case> {
    corpus::corpus()
        .cases
        .iter()
        .filter(|case| case.origin == Origin::Curated)
        .collect()
}

/// The case [`SELECT_VARIABLE`] names, `None` when it is unset.
///
/// # Errors
/// When the variable is set to something that is not a stable identifier of
/// a case in the corpus. A typo must fail loudly rather than replay nothing.
pub fn selected_case() -> Result<Option<&'static Case>, String> {
    selection_from(std::env::var(SELECT_VARIABLE))
}

/// [`selected_case`] for a given reading of the variable, so the parsing can
/// be tested without mutating this process's environment.
///
/// # Errors
/// As [`selected_case`].
pub fn selection_from(value: Result<String, VarError>) -> Result<Option<&'static Case>, String> {
    let text = match value {
        Ok(text) => text,
        Err(VarError::NotPresent) => return Ok(None),
        Err(VarError::NotUnicode(raw)) => {
            return Err(format!("{SELECT_VARIABLE}={raw:?} is not text"));
        }
    };
    let id = CaseId::parse(text.trim()).ok_or_else(|| {
        format!("{SELECT_VARIABLE}={text:?} is not a stable identifier such as local-0001")
    })?;
    corpus::corpus()
        .case(id)
        .map(Some)
        .ok_or_else(|| format!("{SELECT_VARIABLE}={id} names no case in the corpus"))
}

/// A surface area the default run must reach, and whether it has a refusal to
/// reach as well.
#[derive(Debug, Clone, Copy)]
pub struct Area {
    pub name: &'static str,
    pub kinds: &'static [ActionKind],
    pub needs_refusal: bool,
}

/// The areas task b2 names.
pub const AREAS: [Area; 7] = [
    Area {
        name: "host",
        kinds: &[
            ActionKind::HostSetCapacity,
            ActionKind::HostSetRuntimeRoot,
            ActionKind::HostResetRuntimeRoot,
            ActionKind::HostShow,
        ],
        needs_refusal: true,
    },
    Area {
        name: "repository",
        kinds: &[
            ActionKind::RepoAdd,
            ActionKind::RepoList,
            ActionKind::RepoSetCapacity,
            ActionKind::RepoSetScale,
            ActionKind::RepoAddLabel,
            ActionKind::RepoRemoveLabel,
            ActionKind::RepoRemove,
        ],
        needs_refusal: true,
    },
    Area {
        name: "organization",
        kinds: &[
            ActionKind::OrgAdd,
            ActionKind::OrgList,
            ActionKind::OrgSetCapacity,
            ActionKind::OrgSetScale,
            ActionKind::OrgAddLabel,
            ActionKind::OrgRemoveLabel,
            ActionKind::OrgRemove,
        ],
        needs_refusal: true,
    },
    Area {
        name: "workspace",
        kinds: &[ActionKind::RepoSetWorkspace],
        needs_refusal: true,
    },
    Area {
        name: "status",
        kinds: &[ActionKind::StatusJson],
        // A read cannot be refused; the model says so and `check` enforces it.
        needs_refusal: false,
    },
    Area {
        name: "authentication setup",
        kinds: &[ActionKind::AuthLogin],
        // Sign-in has no refusal on the fake GitHub; the refusal that belongs to
        // this area is an add without a credential, counted under repository
        // and organization as `not-authenticated`.
        needs_refusal: false,
    },
    Area {
        name: "authentication teardown",
        kinds: &[ActionKind::AuthLogout],
        needs_refusal: false,
    },
];

/// For each area, how many successful and refused actions `cases` hold,
/// according to the model.
#[must_use]
pub fn area_counts(cases: &[&Case]) -> Vec<(Area, usize, usize)> {
    let mut actions: Vec<(ActionKind, bool)> = Vec::new();
    for case in cases {
        for entry in case.trace().entries {
            if let Entry::Run {
                action, transition, ..
            } = entry
            {
                actions.push((action.kind(), transition.exit.is_success()));
            }
        }
    }
    AREAS
        .iter()
        .map(|area| {
            let of_area = actions.iter().filter(|(kind, _)| area.kinds.contains(kind));
            let succeeded = of_area.clone().filter(|(_, ok)| *ok).count();
            let refused = of_area.filter(|(_, ok)| !*ok).count();
            (*area, succeeded, refused)
        })
        .collect()
}

/// Whether any case signs in through the real device flow and then signs out.
#[must_use]
pub fn has_real_sign_in(cases: &[&Case]) -> bool {
    cases.iter().any(|case| {
        case.steps.iter().any(|step| {
            matches!(
                step,
                crate::cli_chains::action::Step::Run(Action::AuthLogin)
            )
        })
    })
}
