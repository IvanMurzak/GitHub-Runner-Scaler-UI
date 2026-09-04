// owner: f1-cli-auth-host-status

//! `auth login`, `auth status`, `auth logout`.
//!
//! # Where the grant is disclosed, and where it is not
//!
//! `Administration: Read and write` is a grant whose consequences a consent
//! dialog does not explain, so this project states them itself. It used to
//! state them *here*, as twenty-five lines above the device code, on a screen
//! whose entire job is to carry one code and one URL. The permission table is
//! the same for every user and never changes between runs, so after the first
//! sign-in it was a wall the reader had learned to scroll past — which is the
//! opposite of a disclosure.
//!
//! So the text moved to the two places a reader goes *looking* for it, and
//! `auth login` carries none of it:
//!
//! * `README.md`'s `What you are granting` section, before every install
//!   command — pinned end to end by `crates/app/tests/readme_disclosure.rs`;
//! * [`write_permissions`], reachable at any time and without signing in as
//!   `auth status --permissions`.
//!
//! The consequence sentences also still print, unprompted, where the grant is
//! genuinely news: `repo add`/`org add` on a monitor-only policy, whose reader
//! may reasonably assume that "this never starts a runner" implies a narrower
//! permission than it does. That is [`write_grant_consequences`], called from
//! `policy.rs`.
//!
//! # Three actions, counted
//!
//! D3's release gate is *"at most 3 user actions: one command, one code entry,
//! one repository selection"*. That is a number, so this module emits it as one:
//! every action is a line matching `Action N of M:`, which the tests below and
//! `crates/app/tests/auth_onboarding.rs` read back. The gate is then an
//! equality assertion over real command output rather than a reading of the
//! prose.
//!
//! # What never reaches this file's output
//!
//! The **device code** and the **user access token**. `07-security.md` splits
//! the two codes deliberately — *"the user code is shown on screen by design,
//! the device code never is"* — and `crates/github` enforces the split at the
//! type level: `DeviceAuthorization::device_code` hands back a `SecretString`,
//! which this file never calls. The token is moved from
//! `UserAccessToken::secret` straight into `d2`'s store and is never formatted.

use std::fmt::Display;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use runner_manager_domain::model::StartMode;
use runner_manager_domain::store::Store as _;
use runner_manager_github::device_flow::{DeviceAuthorization, DeviceFlow, DeviceFlowError};
use runner_manager_github::{
    AuthenticatedClient, CredentialRenewal, CredentialSource, GithubError, Installation,
    InstallationDiscovery, RepositorySelection, TokioSleeper, UserAccessToken,
};
use runner_manager_platform::secrets::{Removal, SecretStore, SecretStoreError};
use secrecy::SecretString;

use super::{
    AuthCommand, AuthStatusArgs, CliError, Context, Failure, NO_OPERATOR_REMEDY, Styling,
    open_in_browser, write_failed,
};

// ---------------------------------------------------------------------------
// The grant
// ---------------------------------------------------------------------------

/// The grant whose consequences D21 requires this tool to spell out.
pub const CRITICAL_PERMISSION: &str = "Administration: Read and write";

/// The permission table, from `07-security.md`.
///
/// Rendered from data rather than written as prose so that the four rows cannot
/// drift out of column alignment while still being checkable one row at a time.
const PERMISSIONS: [(&str, &str, &str); 4] = [
    (
        "Repository -> Administration",
        "Read and write",
        "Registering a just-in-time runner at repository scope.",
    ),
    (
        "Repository -> Actions",
        "Read",
        "Counting in-progress workflow runs.",
    ),
    (
        "Repository -> Metadata",
        "Read",
        "Mandatory for any repository access.",
    ),
    (
        "Organization -> Self-hosted runners",
        "Read and write",
        "Registering a just-in-time runner at organization scope.",
    ),
];

/// The consequences of the grant, and nothing else.
///
/// # Why the short rendering is the one that prints unprompted
///
/// A permission table is the same on every run, so repeating it is how a
/// reader learns to skip it. What a reader who has already signed in does not
/// necessarily know is what `Administration: Read and write` *also* permits —
/// so that is what prints where the grant is news: the permission named, the
/// three verbs it also authorizes, collaborators, and the fact that watching
/// grants exactly the same set.
///
/// Called from `policy.rs` when a monitor-only policy is created, whose reader
/// may reasonably assume that "this never starts a runner" implies a narrower
/// permission than it does. `policy_commands.rs` asserts each of these
/// sentences, so shortening this further reds a test rather than quietly
/// weakening a disclosure.
///
/// # Errors
/// Whatever `out` fails with.
pub fn write_grant_consequences(out: &mut dyn Write) -> io::Result<()> {
    writeln!(out)?;
    writeln!(
        out,
        "`{CRITICAL_PERMISSION}` is NOT a narrow self-hosted-runner permission."
    )?;
    writeln!(
        out,
        "The same grant also permits DELETING, RENAMING and TRANSFERRING the repository, and"
    )?;
    writeln!(
        out,
        "adding and removing collaborators. Watching grants exactly the same set."
    )?;
    writeln!(out)?;
    Ok(())
}

/// The whole permission set, on request.
///
/// # This is the disclosure `auth login` no longer prints
///
/// The obligation was never that these lines appear on the busiest screen in
/// the product; it is that this tool, and not only GitHub's consent dialog,
/// states what the grant permits, and that a reader can get at the statement
/// without signing in to something first. `README.md` carries it before every
/// install command, and this carries it for anyone already at a prompt —
/// `auth status --permissions`, which needs no credential and issues no
/// request.
///
/// Rendered from [`PERMISSIONS`], the same constant the README's table is
/// checked against, and closed by [`write_grant_consequences`] so that the
/// table and its consequences cannot be shipped apart.
///
/// # Errors
/// Whatever `out` fails with.
pub fn write_permissions(out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "Signing in installs this project's published GitHub App on the repositories or"
    )?;
    writeln!(
        out,
        "organizations you choose. That App declares one permission set, the same for every"
    )?;
    writeln!(out, "user:")?;
    writeln!(out)?;
    for (permission, level, why) in PERMISSIONS {
        writeln!(out, "  {permission:<36}  {level:<15}  {why}")?;
    }
    write_grant_consequences(out)?;
    writeln!(
        out,
        "A monitor-only target grants the same set: an App grants its whole declared set on"
    )?;
    writeln!(
        out,
        "installation, and there is no per-installation subset. Organization scope is"
    )?;
    writeln!(
        out,
        "narrower -- registration there is authorized by `Organization -> Self-hosted"
    )?;
    writeln!(
        out,
        "runners: Read and write` alone -- and is the safer choice where both work."
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "Revoke by uninstalling the App, or by revoking its authorization, in your GitHub"
    )?;
    writeln!(out, "settings: https://github.com/settings/installations")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The three counted actions
// ---------------------------------------------------------------------------

/// D3's budget: *"one command, one code entry, one repository selection"*.
pub const ONBOARDING_ACTIONS: usize = 3;

/// Action 1: the command the operator has, by now, already run.
///
/// Counted even though it is done, because D3's budget counts it: the gate is
/// *three user actions from a clean machine*, and pretending the invocation was
/// free would let a fourth action in under the same number.
fn write_action_one(out: &mut dyn Write, styling: Styling) -> io::Result<()> {
    writeln!(
        out,
        "{} you ran `runner-manager auth login`.",
        styling.step(&format!("Action 1 of {ONBOARDING_ACTIONS} (done):"))
    )
}

/// Action 2: the code entry, on GitHub's own page.
///
/// `opened` reports whether the browser was launched for the operator. The URL
/// is printed either way — a launcher that silently succeeded onto another
/// desktop, or one that never ran at all, must both leave the operator with an
/// address they can open by hand.
fn write_action_two(
    out: &mut dyn Write,
    styling: Styling,
    verification_url: &dyn Display,
    user_code: &str,
    expires_in: Duration,
    opened: bool,
) -> io::Result<()> {
    let url = verification_url.to_string();
    writeln!(out)?;
    writeln!(
        out,
        "{} enter this code at {}{}",
        styling.step(&format!("Action 2 of {ONBOARDING_ACTIONS}:")),
        styling.url(&url),
        if opened { " (opened for you):" } else { ":" }
    )?;
    // The code keeps its own line and the blank lines around it. Everything
    // else on this screen got shorter; this is the one thing the operator is
    // here to read, and crowding it to save two lines would be saving them in
    // the wrong place.
    writeln!(out)?;
    writeln!(out, "    {}", styling.code(&format!(" {user_code} ")))?;
    writeln!(out)?;
    // One line, keeping the two clauses that are load-bearing: the code goes
    // nowhere else (the phishing control `07-security.md` names), and it
    // expires (so a stalled login has an explanation other than a bug).
    writeln!(
        out,
        "Enter it only on that page; expires in ~{} min. Waiting for approval...",
        expires_in.as_secs() / 60
    )?;
    Ok(())
}

/// Action 3: choosing what the App may reach.
fn write_action_three(
    out: &mut dyn Write,
    styling: Styling,
    install_url: &dyn Display,
) -> io::Result<()> {
    // ------------------------------------------------------------------------
    // THE LAST ACTION GETS A BROWSER TOO, AND NOT BY REDIRECT.
    // ------------------------------------------------------------------------
    // A GitHub App can carry a setup URL that the browser is sent to after an
    // installation, but that is a redirect TO something — it needs this tool to
    // be listening on an address GitHub can reach. `07-security.md`'s whole
    // shape is that this product opens no socket of any kind, so the browser is
    // opened from here instead, the same way the device page is.
    //
    // Signing in and installing are two consents on GitHub's side, and an
    // operator who stops after the first has a working credential that reaches
    // nothing. That gap is what this step exists to close, so it opens rather
    // than only printing.
    let url = install_url.to_string();
    let opened = open_in_browser(&url, styling);
    writeln!(out)?;
    writeln!(
        out,
        "{} install the App at {}{}",
        styling.step(&format!("Action 3 of {ONBOARDING_ACTIONS}:")),
        styling.url(&url),
        if opened { " (opened for you)." } else { "." }
    )?;
    writeln!(
        out,
        "Choose only the repositories you want this host to serve."
    )?;
    Ok(())
}

/// Action 3, on a host where it has already been done.
///
/// # Why an action that asks for nothing is still printed
///
/// The counter is the operator's progress bar, and a transcript that stops at
/// *"Action 2 of 3"* reads as one that gave up — which is exactly what a
/// successful sign-in on a host with the App already installed used to look
/// like. The third action was skipped because there was nothing to choose, and
/// nothing said so.
fn write_action_three_already_done(out: &mut dyn Write, styling: Styling) -> io::Result<()> {
    writeln!(out)?;
    writeln!(
        out,
        "{} the App is already installed; nothing to choose.",
        styling.step(&format!("Action 3 of {ONBOARDING_ACTIONS} (done):"))
    )
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// # Errors
/// Whatever the routed command returns.
pub fn dispatch(
    context: &Context,
    command: &AuthCommand,
    styling: Styling,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        AuthCommand::Login(a) => login(context, a.start_at.map(Into::into), a.list, styling, out),
        AuthCommand::Status(a) => status(context, a, styling, out),
        AuthCommand::Logout => logout(context, out),
    }
}

// ---------------------------------------------------------------------------
// auth login
// ---------------------------------------------------------------------------

/// The whole of Journey 1's authentication half.
///
/// # Errors
/// Every class in [`Failure`] that authentication can reach.
/// Names the store this sign-in will write to, before it writes anything.
///
/// Printed unconditionally. The case worth catching is the one where the
/// operator did *not* choose — the default is `boot`, and on macOS that is the
/// System keychain, which needs privilege and is not where a `--start-at login`
/// service will ever look.
fn write_store_choice(out: &mut dyn Write, mode: StartMode, chosen: bool) -> io::Result<()> {
    let scope = match mode {
        StartMode::Boot => "machine-scoped",
        StartMode::Login => "your own",
    };
    // Stated as a fact about the store rather than as "signing in to", because
    // this line is written before the credential is examined and a host that
    // turns out to be signed in already is not signing in to anything.
    //
    // The unchosen case is a parenthetical on the same line rather than a
    // `warning:` of its own. It is a note about a default, printed above the
    // code the operator came here to type, and every line spent on it is a line
    // pushing that code further down the screen.
    if chosen {
        writeln!(out, "Credential store: {scope} (start mode {mode}).")
    } else {
        writeln!(
            out,
            "Credential store: {scope} (start mode {mode}, assumed; `--start-at login` to change)."
        )
    }
}

/// Renews a credential and stores it, in that order and no other.
///
/// # The ordering is the whole point of this type
///
/// GitHub rotates on use: the pair handed back here is live and the pair that
/// bought it is already dead. A renewal that is used before it is stored leaves
/// the host running on a credential it has not recorded -- and if the process
/// stops before it does, the store still holds the dead one and the only way
/// back is an interactive sign-in.
///
/// So the write happens before this returns, and the caller only ever receives
/// a pair that is already durable. A store failure is reported as a failure
/// even though the exchange succeeded, because a credential nobody wrote down
/// is worse than one that was never minted: the old one is dead either way, and
/// at least the failure says so.
#[derive(Debug)]
pub struct StoringRenewal {
    flow: DeviceFlow,
    secrets: Arc<dyn SecretStore>,
}

impl StoringRenewal {
    #[must_use]
    pub fn new(flow: DeviceFlow, secrets: Arc<dyn SecretStore>) -> Self {
        Self { flow, secrets }
    }
}

#[async_trait::async_trait]
impl CredentialRenewal for StoringRenewal {
    async fn renew(&self, refresh_token: &SecretString) -> Result<UserAccessToken, String> {
        let fresh = self
            .flow
            .refresh(refresh_token)
            .await
            .map_err(|source| format!("the refresh exchange failed: {source}"))?;
        self.secrets
            .store(&fresh.to_stored_document())
            .map_err(|source| {
                format!("the renewed credential could not be stored, so it was not used: {source}")
            })?;
        Ok(fresh)
    }
}

/// Reads whatever the store holds now, for a client that has been running long
/// enough for the answer to have changed.
///
/// # Why this is not just the store
///
/// The store deals in bytes; this turns them into the credential document,
/// which is the shape [`CredentialSource`] promises and the shape that carries
/// a refresh half. A credential written before 0.1.11 reads back as a bare
/// token from the same bytes, which is why
/// [`UserAccessToken::from_stored_document`] rather than a parse that could
/// fail.
///
/// Every failure collapses to `None`. A daemon consults this while already
/// handling a `401`, and a store it cannot read leaves it exactly where it was
/// -- with a rejection to report and no better credential to report it against.
/// Logging is deliberate and at `debug`: on a genuinely revoked credential this
/// runs on every poll, and a warning per poll is how a log stops being read.
#[derive(Debug)]
pub struct StoredCredential {
    secrets: Arc<dyn SecretStore>,
}

impl StoredCredential {
    #[must_use]
    pub fn new(secrets: Arc<dyn SecretStore>) -> Self {
        Self { secrets }
    }
}

impl CredentialSource for StoredCredential {
    fn reload(&self) -> Option<UserAccessToken> {
        match self.secrets.load() {
            Ok(Some(secret)) => Some(UserAccessToken::from_stored(secret)),
            Ok(None) => None,
            Err(source) => {
                tracing::debug!(%source, "the credential store could not be re-read");
                None
            }
        }
    }
}

pub fn login(
    context: &Context,
    requested_mode: Option<StartMode>,
    list: bool,
    styling: Styling,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this sign-in");

    // ------------------------------------------------------------------------
    // NO PERMISSION TABLE HERE. IT IS NOT A CUT, IT IS A MOVE.
    // ------------------------------------------------------------------------
    // This command used to open with twenty-five lines naming the App's four
    // permissions and what `Administration: Read and write` also authorizes.
    // The table is identical on every run and identical for every user, so
    // after the first sign-in it was something to scroll past to reach the
    // code -- and a disclosure a reader has been trained to skip is not one.
    //
    // The statement still exists, in the two places somebody looking for it
    // would actually look: `README.md`'s `What you are granting` section,
    // ahead of every install command, and `auth status --permissions`, which
    // needs neither a credential nor a network request. `repo add` still
    // prints the consequence sentences unprompted for a monitor-only policy,
    // which is the one case where the grant genuinely surprises.
    let app = context.app_registration()?;
    let flow = DeviceFlow::new(app.clone(), context.endpoints().clone())
        .map_err(|source| device_flow_failure(&source))?;

    let runtime = super::runtime()?;
    let store = context.store()?;
    // ----------------------------------------------------------------------
    // WHICH STORE, AND WHY IT IS SAID OUT LOUD.
    // ----------------------------------------------------------------------
    // The credential goes into a store chosen by how the agent will start, and
    // the two are genuinely different places -- on macOS, the System keychain
    // against your own login keychain. A daemon reads only the store its start
    // mode names, so a sign-in to the other one leaves a valid credential the
    // service cannot see, and the failure surfaces much later as "no GitHub
    // credential is stored for this daemon's start mode".
    //
    // The default is `boot`, so on a machine that has never installed a service
    // this used to reach for the privileged store with nothing said -- and an
    // operator heading for `--start-at login` had no way to say so and no
    // warning that they were signing in to the wrong half. Hence the flag, and
    // hence the line printed below whether or not it was passed.
    let recorded = context.recorded_start_mode(&store)?;
    let start_mode = requested_mode.unwrap_or(recorded);
    let secrets = context.secret_store(start_mode)?;
    write_store_choice(out, start_mode, requested_mode.is_some()).map_err(failed)?;
    // An explicit choice is recorded, so that `repo add`, `auth status` and the
    // daemon all agree with the sign-in that just happened rather than with a
    // default nobody chose.
    if let Some(mode) = requested_mode
        && mode != recorded
    {
        let mut host = super::host::local_host_or_create(context, &store)?;
        host.service_start_mode = mode;
        store.put_host(&host).map_err(|source| {
            CliError::new(
                Failure::LocalState,
                format!("cannot record the start mode this sign-in used: {source}"),
            )
        })?;
    }

    // ------------------------------------------------------------------------
    // A HOST THAT IS ALREADY SIGNED IN RESUMES; IT DOES NOT SIGN IN AGAIN.
    // ------------------------------------------------------------------------
    // Signing in and installing the App are two consents, and stopping after
    // the first leaves a working credential that reaches nothing. The operator
    // who notices and runs `auth login` again does not need a second device
    // code -- the one they have is fine -- they need the step they missed.
    //
    // So a still-valid credential skips straight to it, which also means the
    // install page opens for them rather than being printed again.
    //
    // Only `Authenticated` short-circuits. A revoked credential must go through
    // the device flow to be replaced, and an unreachable GitHub is not evidence
    // of anything, so both fall through.
    //
    // ------------------------------------------------------------------------
    // AN UNREADABLE STORE IS NOT A REASON TO REFUSE TO SIGN IN.
    // ------------------------------------------------------------------------
    // This read used to be `credential_state(context, &secrets)?`, so a store
    // that could not be read ended the command -- which meant the one action
    // that repairs an unreadable store was the one action that would not run
    // against one. Two real failures reach it: a macOS keychain item whose ACL
    // no longer names this binary after a self-upgrade (`-25293`), and a
    // Windows blob whose owner moved to the service account when the daemon
    // renewed. Both leave an operator holding the correct instructions and a
    // command that refuses them.
    //
    // Nothing is lost by continuing. A value that cannot be read cannot be
    // resumed, which is the only question being asked here, and the sign-in
    // that follows replaces it. What the operator gets instead of a dead end is
    // a line saying so.
    let resumable = match secrets.load() {
        Ok(existing) => existing,
        Err(_) => {
            // One line, and it does not carry the reason. That reason runs to a
            // paragraph — `secrets::locked_out` has to explain a keychain ACL
            // to somebody who has never met one — and printing it here buries
            // the code the operator came for under a diagnosis of a credential
            // this very command is about to replace. `status` and `auth status`
            // both still report it in full, which is where somebody who wants
            // the diagnosis is looking.
            writeln!(
                out,
                "\nThe credential already there could not be read, so this replaces it rather \
                 than resuming it. `auth status` says why."
            )
            .map_err(failed)?;
            None
        }
    };
    if let Some(secret) = resumable
        && let CredentialState::Authenticated(discovery) = credential_state_of(context, secret)?
    {
        writeln!(out, "Already signed in, so no new code is needed.").map_err(failed)?;
        write_discovery(out, styling, &discovery, true, list).map_err(failed)?;
        return Ok(());
    }

    // Counted only once the sign-in is actually going to happen. A host that
    // short-circuits above prints no `Action 1 of 3`, because actions 2 and 3
    // are not coming and a budget with two thirds of it missing reads as a
    // transcript that was cut off.
    write_action_one(out, styling).map_err(failed)?;

    let authorization = runtime
        .block_on(flow.start())
        .map_err(|source| device_flow_failure(&source))?;

    write_login_prompt(out, styling, &flow, &authorization).map_err(failed)?;
    out.flush().map_err(failed)?;

    let token = runtime
        .block_on(flow.complete(&authorization, &TokioSleeper))
        .map_err(|source| device_flow_failure(&source))?;

    // The value is exposed exactly once, here, as the argument to `store`, and
    // is never bound to a name that could be formatted, logged, or returned.
    secrets
        // The document, not the bare token: it carries the refresh half and
        // the two expiry instants when the App issues them, and reads back as a
        // bare token when it does not. See `UserAccessToken::to_stored_document`.
        .store(&token.to_stored_document())
        .map_err(|source| secret_store_failure(&source))?;

    // ---- what the credential reaches, and the third action if any --------
    let client = AuthenticatedClient::new(context.endpoints().clone(), token, context.clock())
        .map_err(|source| github_failure(&source))?;

    let discovery = runtime
        .block_on(client.discover_installations(&app))
        .map_err(|source| github_failure(&source))?;

    // The counted actions come before the outcome, all three of them. An
    // install that is still to be done announces itself from inside
    // `write_discovery`, below the sign-in line, because it is the next thing
    // the operator has to go and do; one that is already done is announced
    // here, above it, because it is part of what just finished.
    if matches!(discovery, InstallationDiscovery::Installed(_)) {
        write_action_three_already_done(out, styling).map_err(failed)?;
    }

    // The scope, not the full location. The location is a keychain path plus an
    // item name, it was already named on the first line of this command, and
    // `host show` prints it whenever somebody actually needs it. What belongs
    // here is the claim: one store, and nowhere else.
    writeln!(
        out,
        "\nSigned in. The token is in the {}-scoped store and nowhere else.",
        secrets.scope()
    )
    .map_err(failed)?;

    write_discovery(out, styling, &discovery, true, list).map_err(failed)?;
    Ok(())
}

/// The device-flow prompt: the canonical page, and the code to type on it.
///
/// The URL comes from `DeviceFlow::verification_url` — this product's own
/// constant — and **not** from `DeviceAuthorization::verification_uri`, even
/// though GitHub sends one. `07-security.md`'s phishing control is that *"the
/// tool prints the canonical `github.com/login/device` URL and never proxies or
/// embeds the approval page"*. `crates/github` already refuses an authorization
/// whose `verification_uri` sits on another origin, so the two agree today;
/// printing the constant means the printed URL does not depend on a remote
/// party's string even if that check is ever loosened.
fn write_login_prompt(
    out: &mut dyn Write,
    styling: Styling,
    flow: &DeviceFlow,
    authorization: &DeviceAuthorization,
) -> io::Result<()> {
    // Opened BEFORE the prompt is written, so the line the operator reads
    // states what already happened rather than what is about to. The launcher
    // is best effort and the URL is printed either way, so a browser that never
    // appears costs a copy-paste and nothing else.
    //
    // It is also opened AFTER the disclosure has been written and flushed by
    // the caller, which is the ordering `07-security.md` fixes: "`auth login`
    // prints the same statement before opening the browser".
    let url = flow.verification_url().to_string();
    let opened = open_in_browser(&url, styling);
    write_action_two(
        out,
        styling,
        &url,
        authorization.user_code(),
        authorization.expires_in(),
        opened,
    )
}

// ---------------------------------------------------------------------------
// auth status
// ---------------------------------------------------------------------------

/// What `auth status` concluded about the stored credential.
///
/// `03-control-flows.md` flow 4.3 separates the two authentication answers and
/// `c2` implements the separation, so collapsing them here would throw away a
/// distinction the layer below took trouble to keep: a lockout tells an
/// operator *"nothing is wrong with your credential, wait"*, and re-running
/// `auth login` during one makes it worse.
///
/// [`CredentialState::Unreachable`] is a fifth state and is here for the same
/// reason. `f1`'s Definition of Done names four; folding an offline host into
/// [`CredentialState::Revoked`] would tell an operator with a dropped
/// connection to sign in again, which is the wrong remedy stated confidently.
#[derive(Debug)]
pub enum CredentialState {
    /// No value in the store. The ordinary state before `auth login`.
    NotAuthenticated,
    /// GitHub accepted the credential.
    Authenticated(Box<InstallationDiscovery>),
    /// GitHub rejected it: uninstalled, or the authorization was revoked.
    Revoked,
    /// GitHub's temporary authentication lockout. Wait; do not re-authenticate.
    LockedOut { retry_after_secs: u64 },
    /// GitHub could not be reached, so nothing was learned.
    Unreachable { detail: String },
}

impl CredentialState {
    /// The stable name `status --json` and the log field use.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotAuthenticated => "not_authenticated",
            Self::Authenticated(_) => "authenticated",
            Self::Revoked => "revoked",
            Self::LockedOut { .. } => "locked_out",
            Self::Unreachable { .. } => "unreachable",
        }
    }

    /// The exit code this state ends the command with.
    ///
    /// `authenticated` is the only success. A script that ran `auth status` and
    /// got zero for "no credential at all" would have nothing to gate on.
    #[must_use]
    pub const fn failure(&self) -> Option<Failure> {
        match self {
            Self::Authenticated(_) => None,
            Self::NotAuthenticated => Some(Failure::NotAuthenticated),
            Self::Revoked => Some(Failure::AuthenticationFailed),
            Self::LockedOut { .. } => Some(Failure::AuthenticationLockout),
            Self::Unreachable { .. } => Some(Failure::GithubUnavailable),
        }
    }

    /// The command that clears this state, or the one that re-checks it.
    #[must_use]
    pub const fn remedy(&self) -> &'static str {
        match self {
            Self::NotAuthenticated | Self::Revoked => "runner-manager auth login",
            Self::LockedOut { .. } => {
                "wait for the lockout to elapse, then runner-manager auth status"
            }
            Self::Unreachable { .. } => {
                "check this host's network, then runner-manager auth status"
            }
            Self::Authenticated(_) => "runner-manager auth status",
        }
    }
}

/// Loads the credential and asks GitHub what it is worth.
///
/// Shared with `status`'s renderer and available to `f2`, which needs the same
/// answers before it will create a policy.
///
/// # Errors
/// [`Failure::SecretStore`] when the store itself cannot be read, and
/// [`Failure::AppNotPublished`] when this build has no registration. Every
/// *authentication* outcome is a [`CredentialState`] rather than an error,
/// because all five are answers rather than malfunctions.
pub fn credential_state(
    context: &Context,
    secrets: &dyn SecretStore,
) -> Result<CredentialState, CliError> {
    let Some(secret) = secrets
        .load()
        .map_err(|source| secret_store_failure(&source))?
    else {
        return Ok(CredentialState::NotAuthenticated);
    };
    credential_state_of(context, secret)
}

/// What GitHub makes of a credential already in hand.
///
/// Split out of [`credential_state`] so that `login` can decide for itself what
/// an unreadable store means. To `status` it is an error worth reporting; to
/// `login` it is the ordinary condition of a host that is about to sign in
/// anyway, and treating it as fatal there is what made the store's own repair
/// refuse to run against a store that needed repairing.
///
/// # Errors
/// [`Failure::AppNotPublished`] when this build has no registration. Every
/// authentication outcome is a [`CredentialState`].
pub fn credential_state_of(
    context: &Context,
    secret: SecretString,
) -> Result<CredentialState, CliError> {
    let app = context.app_registration()?;
    let client = AuthenticatedClient::new(
        context.endpoints().clone(),
        UserAccessToken::from_stored(secret),
        context.clock(),
    )
    .map_err(|source| github_failure(&source))?;

    let runtime = super::runtime()?;
    match runtime.block_on(client.discover_installations(&app)) {
        Ok(discovery) => Ok(CredentialState::Authenticated(Box::new(discovery))),
        Err(GithubError::AuthenticationFailed) => Ok(CredentialState::Revoked),
        Err(GithubError::AuthenticationLockout { retry_after }) => Ok(CredentialState::LockedOut {
            retry_after_secs: retry_after.as_secs(),
        }),
        Err(source @ GithubError::Transport(_)) => Ok(CredentialState::Unreachable {
            detail: source.to_string(),
        }),
        Err(source) => Err(github_failure(&source)),
    }
}

/// # Errors
/// The state's own [`CredentialState::failure`], plus store and registration
/// failures.
pub fn status(
    context: &Context,
    args: &AuthStatusArgs,
    styling: Styling,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("this credential's status");

    // `--permissions` describes the App, not this host's credential, so it is
    // answered before anything is loaded: an operator deciding whether to sign
    // in at all can read the grant on a machine that never has.
    if args.permissions {
        write_permissions(out).map_err(failed)?;
        writeln!(out).map_err(failed)?;
    }

    let store = context.store()?;
    let start_mode = context.recorded_start_mode(&store)?;
    let secrets = context.secret_store(start_mode)?;
    let state = credential_state(context, &secrets)?;

    writeln!(out, "Credential: {}", state.as_str()).map_err(failed)?;
    writeln!(out, "Store:      {}", secrets.location()).map_err(failed)?;
    write_state_explanation(out, styling, &state, args.list).map_err(failed)?;

    match state.failure() {
        None => Ok(()),
        Some(class) => Err(CliError::with_remedy(
            class,
            format!("the stored credential is {}", state.as_str()),
            state.remedy(),
        )),
    }
}

/// One screenful per state, and never the wrong remedy stated confidently.
fn write_state_explanation(
    out: &mut dyn Write,
    styling: Styling,
    state: &CredentialState,
    list: bool,
) -> io::Result<()> {
    // The blank line belongs to each arm rather than to the match, because
    // `write_discovery` opens with one of its own and two in a row read as a
    // section break that is not there.
    match state {
        CredentialState::NotAuthenticated => {
            writeln!(out)?;
            writeln!(
                out,
                "There is no GitHub credential on this host. Nothing has been revoked and"
            )?;
            writeln!(
                out,
                "nothing is broken -- this is what a machine looks like before `auth login`."
            )?;
        }
        CredentialState::Authenticated(discovery) => {
            write_discovery(out, styling, discovery, false, list)?;
        }
        CredentialState::Revoked => {
            writeln!(out)?;
            writeln!(
                out,
                "GitHub no longer accepts the stored credential. That happens when the App is"
            )?;
            writeln!(
                out,
                "uninstalled or its authorization is revoked, and it is not something this host"
            )?;
            writeln!(out, "can undo: obtain a fresh token.")?;
        }
        CredentialState::LockedOut { retry_after_secs } => {
            writeln!(out)?;
            writeln!(
                out,
                "GitHub has temporarily locked out authentication for this credential. There is"
            )?;
            writeln!(
                out,
                "nothing wrong with the token itself, and signing in again will not help -- it"
            )?;
            writeln!(
                out,
                "extends the lockout. Wait about {retry_after_secs} seconds and ask again."
            )?;
        }
        CredentialState::Unreachable { detail } => {
            writeln!(out)?;
            writeln!(
                out,
                "GitHub could not be reached, so nothing was learned about the stored"
            )?;
            writeln!(out, "credential: it may be perfectly good. {detail}")?;
        }
    }
    Ok(())
}

/// Renders what a credential reaches.
///
/// `07-security.md`: *"`auth status` shows which repositories the token can
/// reach, so an over-broad installation is visible rather than assumed."*
///
/// # The roll call is `--list`; the answer is not
///
/// An installation on an active account reaches hundreds of repositories, and
/// one set to `all` reaches every repository created on it from now on. Printing
/// every name by default cost several screens to say something the count and
/// the over-broad warning say in three lines -- and it pushed those three lines
/// off the top of the terminal, so the output that existed to make an
/// over-broad installation *visible* was the output hiding it.
///
/// So what is unconditional is what answers the question:
///
/// * the count of reachable repositories and organizations;
/// * every installation, by account, with its selection;
/// * the `all`-selection warning, which no list of today's names can carry.
///
/// `list` adds the names underneath each installation. Nothing is dropped from
/// the default output except the roll call itself, and the line that says how to
/// get it is printed where the roll call used to be.
fn write_discovery(
    out: &mut dyn Write,
    styling: Styling,
    discovery: &InstallationDiscovery,
    onboarding: bool,
    list: bool,
) -> io::Result<()> {
    match discovery {
        InstallationDiscovery::NotInstalled { install_url } => {
            if onboarding {
                write_action_three(out, styling, install_url)?;
            } else {
                writeln!(out)?;
                writeln!(
                    out,
                    "The App is installed nowhere this credential can reach, so it sees no"
                )?;
                writeln!(out, "repositories and no organizations.")?;
                writeln!(out)?;
                writeln!(out, "  Install it: {install_url}")?;
            }
        }
        InstallationDiscovery::Indeterminate { skipped } => {
            writeln!(out)?;
            writeln!(
                out,
                "GitHub reported {skipped} installation(s) this tool could not describe, and no"
            )?;
            writeln!(
                out,
                "others. Whether the App is installed cannot be determined from here, so no"
            )?;
            writeln!(
                out,
                "installation URL is offered: it might be the wrong advice."
            )?;
        }
        InstallationDiscovery::Installed(targets) => {
            let repositories = targets.repositories();
            let organizations = targets.organizations();
            writeln!(out)?;
            writeln!(
                out,
                "Reaches {} repositor{} and {} organization{}:",
                repositories.len(),
                if repositories.len() == 1 { "y" } else { "ies" },
                organizations.len(),
                if organizations.len() == 1 { "" } else { "s" },
            )?;
            for installation in targets.installations() {
                write_installation(out, installation, list)?;
            }
            if targets.skipped() > 0 {
                writeln!(
                    out,
                    "  NOTE: {} further installation(s) could not be described, so this list is \
                     incomplete rather than merely short.",
                    targets.skipped()
                )?;
            }
            let over_broad = targets.over_broad();
            if !over_broad.is_empty() {
                writeln!(
                    out,
                    "  warning: {} installation(s) reach ALL repositories on the account, \
                     including ones created later.",
                    over_broad.len()
                )?;
            }
            // Last, deliberately. This is the least urgent line in the block
            // and the warning above it is the most, so the hint does not sit
            // between an operator and the sentence they need to read.
            if !list && !repositories.is_empty() {
                writeln!(out, "  Add --list to name every repository.")?;
            }
        }
    }
    Ok(())
}

/// One installation, and its repositories only when they were asked for.
///
/// The count comes along on the installation's own line either way, so the
/// default output still distinguishes an installation reaching two
/// repositories from one reaching two hundred -- which is the difference a
/// reader is scanning for, and the reason the roll call can be optional at all.
fn write_installation(
    out: &mut dyn Write,
    installation: &Installation,
    list: bool,
) -> io::Result<()> {
    let selection = match installation.repository_selection {
        RepositorySelection::All => "ALL repositories",
        RepositorySelection::Selected => "selected repositories",
    };
    writeln!(
        out,
        "  {} ({}, installation {}, {selection}, {} reachable)",
        installation.account,
        installation.account.kind(),
        installation.id,
        installation.repositories.len(),
    )?;
    if list {
        for repository in &installation.repositories {
            writeln!(out, "      {repository}")?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// auth logout
// ---------------------------------------------------------------------------

/// The sentence `auth logout` exists to say out loud.
///
/// `07-security.md`: *"`auth logout` purges it locally; uninstalling the App
/// invalidates it at GitHub, which is the authoritative revocation."* A logout
/// that reported success and stopped would leave an operator believing a live
/// bearer token had been revoked when only a local copy was deleted — and
/// `05-infrastructure.md`'s credential-disclosure procedure is built on the
/// operator knowing the difference.
pub const REVOCATION_HEADLINE: &str = "Authoritative revocation is uninstalling the App at GitHub.";

/// Writes what logging out does and, more importantly, what it does not.
///
/// # Errors
/// Whatever `out` fails with.
pub fn write_revocation_notice(out: &mut dyn Write) -> io::Result<()> {
    writeln!(out)?;
    writeln!(
        out,
        "This host can no longer talk to GitHub, and that is the whole of what just happened."
    )?;
    writeln!(
        out,
        "The token itself is still valid at GitHub, and any other host holding a copy still"
    )?;
    writeln!(out, "works.")?;
    writeln!(out)?;
    writeln!(out, "{REVOCATION_HEADLINE} Revoking its authorization does")?;
    writeln!(out, "the same. Either is done in your GitHub settings:")?;
    writeln!(out)?;
    writeln!(
        out,
        "    https://github.com/settings/installations    (your own account)"
    )?;
    writeln!(
        out,
        "    an organization's Settings -> GitHub Apps    (an organization)"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "Neither needs this project's cooperation, and neither is something `auth logout`"
    )?;
    writeln!(out, "can do on your behalf.")?;
    Ok(())
}

/// Purges the local credential and says what that does and does not achieve.
///
/// Both [`Removal`] variants are success. `05-infrastructure.md`'s
/// credential-disclosure response is *"run `auth logout` on every host"*,
/// precisely because the operator does not know which hosts hold a value, and a
/// host that held none must not fail the procedure.
///
/// # Errors
/// [`Failure::SecretStore`] when a value is there and cannot be removed —
/// which the same procedure needs to hear about, loudly.
pub fn logout(context: &Context, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("this sign-out");
    let store = context.store()?;
    let start_mode = context.recorded_start_mode(&store)?;
    let secrets = context.secret_store(start_mode)?;

    let removal = secrets
        .delete()
        .map_err(|source| secret_store_failure(&source))?;

    match removal {
        Removal::Removed => writeln!(
            out,
            "Removed the stored credential from the {}.",
            secrets.location()
        ),
        Removal::AlreadyAbsent => writeln!(
            out,
            "There was no stored credential in the {}. Nothing to remove.",
            secrets.location()
        ),
    }
    .map_err(failed)?;

    write_revocation_notice(out).map_err(failed)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Failure mapping
// ---------------------------------------------------------------------------

/// Turns `c2`'s error matrix into exit codes and one-screenful advice.
///
/// Every arm names a command or states that no operator command helps, because
/// `f1` requires a failure to name what fixes it — and for
/// [`DeviceFlowError::AppMisconfigured`] the honest answer is that nothing the
/// operator can type does.
fn device_flow_failure(source: &DeviceFlowError) -> CliError {
    match source {
        DeviceFlowError::AccessDenied => CliError::with_remedy(
            Failure::AuthenticationDeclined,
            "the login was declined on GitHub. Nothing was stored and nothing changed.",
            "runner-manager auth login   (only if the refusal was a mistake)",
        ),
        DeviceFlowError::Expired | DeviceFlowError::IncorrectDeviceCode => CliError::with_remedy(
            Failure::AuthenticationExpired,
            format!("{source}. Codes are single-use and short-lived."),
            "runner-manager auth login",
        ),
        DeviceFlowError::AppMisconfigured { .. } => CliError::new(
            Failure::AppMisconfigured,
            format!(
                "{source}. This is a defect in the published App, not in this host's setup, \
                 so {NO_OPERATOR_REMEDY}. Please report it against the project."
            ),
        ),
        DeviceFlowError::UntrustedVerificationUri { origin } => CliError::new(
            Failure::UnusableResponse,
            format!(
                "refusing to continue: the device-flow response pointed the approval page at \
                 {origin:?}, which is not GitHub. Your code has not been shown and nothing has \
                 been stored. Treat this as an interception attempt on this network -- \
                 {NO_OPERATOR_REMEDY}, and signing in again from here would present the code \
                 to the same party."
            ),
        ),
        DeviceFlowError::Transport(_) => CliError::with_remedy(
            Failure::GithubUnavailable,
            format!("{source}. Nothing was stored."),
            "check this host's network, then runner-manager auth login",
        ),
        DeviceFlowError::Status { .. } | DeviceFlowError::Unexpected { .. } => {
            CliError::with_remedy(
                Failure::GithubRefused,
                format!("{source}. Nothing was stored."),
                "runner-manager auth login",
            )
        }
        // A response that did not decode says nothing about the login itself,
        // so a fresh one is a reasonable thing to try -- unlike the two arms
        // above it, which are answers rather than accidents.
        DeviceFlowError::Decode { .. } | DeviceFlowError::Malformed { .. } => {
            CliError::with_remedy(
                Failure::UnusableResponse,
                format!("{source}. Nothing was stored."),
                "runner-manager auth login",
            )
        }
        DeviceFlowError::Config(_) => CliError::new(
            Failure::AppNotPublished,
            format!(
                "the App registration this build carries is unusable: {source}. That is a \
                 property of the build rather than of this host, so {NO_OPERATOR_REMEDY}."
            ),
        ),
    }
}

fn github_failure(source: &GithubError) -> CliError {
    match source {
        GithubError::AuthenticationFailed => CliError::with_remedy(
            Failure::AuthenticationFailed,
            source.to_string(),
            "runner-manager auth login",
        ),
        GithubError::AuthenticationLockout { .. } => CliError::with_remedy(
            Failure::AuthenticationLockout,
            format!("{source}. The credential itself is fine."),
            "wait for the lockout to elapse, then runner-manager auth status",
        ),
        GithubError::Transport(_) => CliError::with_remedy(
            Failure::GithubUnavailable,
            source.to_string(),
            "check this host's network, then runner-manager auth status",
        ),
        GithubError::Forbidden { .. } | GithubError::Status { .. } => CliError::with_remedy(
            Failure::GithubRefused,
            source.to_string(),
            "runner-manager auth status",
        ),
        // Same judgement as the device flow's matching arm: a response that
        // did not decode says nothing about the credential, so asking again is
        // a reasonable thing to try. `auth status` rather than `auth login`,
        // because the sibling `Forbidden`/`Status` arms above send the operator
        // there and a decode failure is no more a credential problem than they
        // are.
        GithubError::Decode { .. } | GithubError::Malformed { .. } => CliError::with_remedy(
            Failure::UnusableResponse,
            source.to_string(),
            "runner-manager auth status",
        ),
        // A property of the build, not of this host. No operator command
        // changes it, and offering one would send somebody round a loop.
        GithubError::Config(_) => CliError::new(
            Failure::AppNotPublished,
            format!("{source}. That is a property of this build, so {NO_OPERATOR_REMEDY}."),
        ),
    }
}

/// Maps `d2`'s failures.
///
/// None of these carries the stored value — `d2` documents that as an invariant
/// of its error type, *"no variant carries the stored value, and none ever
/// may"* — so rendering `source` verbatim cannot leak one.
fn secret_store_failure(source: &SecretStoreError) -> CliError {
    match source {
        SecretStoreError::Corrupt { .. } => CliError::with_remedy(
            Failure::SecretStore,
            source.to_string(),
            "runner-manager auth logout, then runner-manager auth login",
        ),
        SecretStoreError::Resolve { .. }
        | SecretStoreError::Store { .. }
        | SecretStoreError::Load { .. }
        | SecretStoreError::Delete { .. }
        | SecretStoreError::Inspect { .. } => CliError::with_remedy(
            Failure::SecretStore,
            source.to_string(),
            "runner-manager host show   (reports where the store is and what protects it)",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prefix every counted action line starts with.
    const ACTION_PREFIX: &str = "Action ";

    // -----------------------------------------------------------------------
    // THE ACTION ORACLE LIVES IN THE TEST MODULE, AND SO DOES ITS TWIN IN
    // `crates/app/tests/auth_onboarding.rs`.
    // -----------------------------------------------------------------------
    // `crates/app` is a `[[bin]]` with no `[lib]` target -- `a1` owns the
    // manifest and this task may not add one -- so an integration test cannot
    // import anything from here and has to carry its own copy. Keeping the
    // oracle out of the product code makes that duplication honest: it is a
    // measuring instrument, not behaviour, and two independent readings of the
    // same output is what the gate wants anyway. If the two ever disagree, one
    // of them fails, which is the point.

    /// One counted onboarding action, as it appeared in the output.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct OnboardingAction {
        /// `N` in `Action N of M`.
        index: usize,
        /// `M` in `Action N of M`.
        total: usize,
        /// Everything after the colon.
        text: String,
    }

    /// Reads the counted actions back out of a transcript.
    ///
    /// Deliberately a *parser over the rendered output* rather than a getter on a
    /// list the renderer also uses. A gate that asked the renderer how many actions
    /// it intended would pass for a renderer that intended three and printed four.
    #[must_use]
    fn onboarding_actions(transcript: &str) -> Vec<OnboardingAction> {
        let mut found = Vec::new();
        for line in transcript.lines() {
            let Some(rest) = line.trim_start().strip_prefix(ACTION_PREFIX) else {
                continue;
            };
            let Some((counts, text)) = rest.split_once(':') else {
                continue;
            };
            let Some((index, total)) = counts.trim().split_once(" of ") else {
                continue;
            };
            // `Action 1 of 3 (done)` — the parenthetical is a note, not a count.
            let total = total.split_whitespace().next().unwrap_or_default();
            let (Ok(index), Ok(total)) = (index.trim().parse::<usize>(), total.parse::<usize>())
            else {
                continue;
            };
            found.push(OnboardingAction {
                index,
                total,
                text: text.trim().to_string(),
            });
        }
        found
    }

    /// Whether a transcript's actions honour D3's budget.
    ///
    /// `Err` carries what is wrong, so the gate's failure message names the defect
    /// instead of only the count. Shared by the unit tests below and by the
    /// integration walkthrough that drives the real binary.
    ///
    /// # Errors
    /// A budget of anything other than [`ONBOARDING_ACTIONS`], more actions than
    /// that, a gap or repeat in the numbering, or none at all.
    fn check_onboarding_budget(actions: &[OnboardingAction]) -> Result<(), String> {
        if actions.is_empty() {
            return Err(
                "the transcript counted no onboarding actions at all, so any count read \
                        from it would be vacuous"
                    .to_string(),
            );
        }
        for action in actions {
            if action.total != ONBOARDING_ACTIONS {
                return Err(format!(
                    "action {} announces a budget of {}, but D3 allows {ONBOARDING_ACTIONS}",
                    action.index, action.total
                ));
            }
        }
        if actions.len() > ONBOARDING_ACTIONS {
            return Err(format!(
                "the transcript asks the operator for {} actions, over D3's budget of \
                 {ONBOARDING_ACTIONS}",
                actions.len()
            ));
        }
        for (position, action) in actions.iter().enumerate() {
            let expected = position + 1;
            if action.index != expected {
                return Err(format!(
                    "action {} appears in position {expected}: the numbering must be dense and \
                     ascending, or a skipped step reads as a smaller budget than it is",
                    action.index
                ));
            }
        }
        Ok(())
    }

    fn text(render: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> String {
        let mut buffer = Vec::new();
        render(&mut buffer).expect("writing to a Vec cannot fail");
        String::from_utf8(buffer).expect("the copy is ASCII")
    }

    /// A transcript built from the *product's own* writers, in the order
    /// [`login`] calls them.
    ///
    /// ## This is a copy-ordering test, not a product-ordering test
    ///
    /// Read that sentence before trusting anything below it. The order here is
    /// **hardcoded in this function**, so reordering the writers inside `login`
    /// changes no byte of this transcript and fails nothing in this module.
    /// `crates/app` is a `[[bin]]` with no `[lib]` target and
    /// `DeviceAuthorization` has no public constructor, so there is no way to
    /// drive the real `login` from a unit test.
    ///
    /// **The control for product output is
    /// `crates/app/tests/auth_onboarding.rs`** — real binary, real stdout,
    /// which is where the budget and the absence of the permission table are
    /// measured against what the command actually prints.
    fn transcript() -> String {
        text(|out| {
            write_action_one(out, Styling::plain())?;
            write_action_two(
                out,
                Styling::plain(),
                &"https://github.com/login/device",
                "WDJB-MJHT",
                Duration::from_secs(900),
                false,
            )?;
            write_action_three(
                out,
                Styling::plain(),
                &"https://github.com/apps/example/installations/new",
            )
        })
    }

    // -- the grant -------------------------------------------------------

    /// The login screen carries no permission table.
    ///
    /// Asserted as an absence, and absences are only worth asserting when the
    /// thing looked for demonstrably exists somewhere: every needle below is
    /// checked to be present in [`write_permissions`] first, so a renamed
    /// permission cannot turn this into a test that scans a transcript for
    /// strings no renderer produces any more.
    #[test]
    fn the_login_screen_carries_no_permission_table() {
        let transcript = transcript();
        let permissions = text(write_permissions);

        let mut needles = vec![CRITICAL_PERMISSION, "DELETING", "monitor-only"];
        for (permission, _, _) in PERMISSIONS {
            needles.push(permission);
        }
        for needle in needles {
            assert!(
                permissions.contains(needle),
                "`{needle}` must be somewhere a reader can reach it, or the assertion below                  passes because nothing renders it at all rather than because `login`                  stopped rendering it"
            );
            assert!(
                !transcript.contains(needle),
                "`auth login` must not print `{needle}`. The table is identical on every run,                  and it sat above the one code the operator came for:
{transcript}"
            );
        }
    }

    /// The grant is not gone, only moved: `auth status --permissions` says
    /// everything the login screen used to, and says it without a credential.
    #[test]
    fn the_permission_report_states_what_the_administration_grant_actually_permits() {
        let permissions = text(write_permissions);
        assert!(
            permissions.contains(CRITICAL_PERMISSION),
            "the exact grant must be named"
        );
        for consequence in ["DELETING", "RENAMING", "TRANSFERRING"] {
            assert!(
                permissions.contains(consequence),
                "{consequence} is one of the three consequences `07-security.md` names for                  `{CRITICAL_PERMISSION}`; a table of permission names without them is the                  disclosure GitHub's own consent screen already gives"
            );
        }
        assert!(
            permissions.contains("monitor-only"),
            "D21's accepted cost is that this binds a dashboard-only user too, who is the              user least likely to expect a write grant"
        );
        assert!(
            permissions.contains("Organization scope is"),
            "`07-security.md` requires the safer scope to be recommended where both work"
        );
        assert!(
            permissions.contains("Revoke"),
            "and the reader must be told the grant is theirs to withdraw"
        );
        for (permission, level, _) in PERMISSIONS {
            assert!(
                permissions.contains(permission),
                "the permission table must list {permission}"
            );
            assert!(permissions.contains(level));
        }
    }

    /// The three sentences `repo add` prints unprompted are a subset of the
    /// full report, so the two renderings of one obligation cannot drift into
    /// saying different things.
    #[test]
    fn the_permission_report_contains_the_consequence_sentences_verbatim() {
        let consequences = text(write_grant_consequences);
        let permissions = text(write_permissions);
        for sentence in consequences.lines().filter(|line| !line.trim().is_empty()) {
            assert!(
                permissions.contains(sentence),
                "`write_permissions` must carry `write_grant_consequences` verbatim, or the                  monitor-only warning and the full report are two disclosures that can                  disagree. Missing:
{sentence}"
            );
        }
    }

    // -- the three-action budget -------------------------------------------

    #[test]
    fn a_clean_machine_reaches_an_authenticated_tool_in_three_actions() {
        let transcript = transcript();
        let actions = onboarding_actions(&transcript);

        assert_eq!(
            actions.len(),
            ONBOARDING_ACTIONS,
            "D3's release gate is three: one command, one code entry, one repository \
             selection. Found: {actions:#?}"
        );
        check_onboarding_budget(&actions).expect("the transcript must honour D3's budget");

        assert!(
            actions[0].text.contains("runner-manager auth login"),
            "the first action is the one command D3 budgets for: {:?}",
            actions[0].text
        );
        assert!(
            actions[1].text.contains("github.com/login/device"),
            "the second action is the code entry, on GitHub's own page: {:?}",
            actions[1].text
        );
        assert!(
            actions[2].text.contains("installations/new"),
            "the third action is the repository selection: {:?}",
            actions[2].text
        );
    }

    /// The counter must reject a fourth action, or the gate above is a spelling
    /// check over three lines that happen to exist.
    #[test]
    fn the_budget_check_rejects_a_fourth_action() {
        let mut transcript = transcript();
        transcript.push_str("Action 4 of 3: run `runner-manager auth confirm`.\n");

        let actions = onboarding_actions(&transcript);
        assert_eq!(actions.len(), 4, "the parser must see the extra action");
        let rejected = check_onboarding_budget(&actions)
            .expect_err("four actions must not pass a budget of three");
        assert!(
            rejected.contains("over D3's budget"),
            "the rejection must name the budget: {rejected}"
        );
    }

    /// A renderer that renumbered to `1 of 4 .. 4 of 4` keeps the numbering
    /// dense and ascending, so density alone is not the check.
    #[test]
    fn the_budget_check_rejects_a_widened_budget() {
        let widened = "Action 1 of 4: a\nAction 2 of 4: b\nAction 3 of 4: c\nAction 4 of 4: d\n";
        let actions = onboarding_actions(widened);
        assert_eq!(actions.len(), 4);
        let rejected =
            check_onboarding_budget(&actions).expect_err("a budget of four is not D3's budget");
        assert!(rejected.contains("announces a budget of 4"), "{rejected}");
    }

    /// An empty transcript must fail rather than pass vacuously: "no actions"
    /// is not "no more than three actions".
    #[test]
    fn the_budget_check_rejects_a_transcript_it_could_not_parse() {
        let rejected = check_onboarding_budget(&[])
            .expect_err("counting nothing must not read as honouring the budget");
        assert!(rejected.contains("vacuous"), "{rejected}");
    }

    #[test]
    fn the_action_parser_ignores_lines_that_only_look_like_actions() {
        let noise = "Actions are counted.\nAction two of three: no.\nAction 1 of 3: yes.\n";
        let actions = onboarding_actions(noise);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].index, 1);
        assert_eq!(actions[0].total, 3);
        assert_eq!(actions[0].text, "yes.");
    }

    /// The user code is displayed by design; the device code never is. This
    /// pins the half that is deliberate, so that a later edit removing the code
    /// from the prompt fails loudly rather than producing a login nobody can
    /// complete.
    #[test]
    fn the_prompt_shows_the_user_code_and_names_only_githubs_own_page() {
        let prompt = text(|out| {
            write_action_two(
                out,
                Styling::plain(),
                &"https://github.com/login/device",
                "WDJB-MJHT",
                Duration::from_secs(900),
                false,
            )
        });
        assert!(prompt.contains("WDJB-MJHT"));
        assert!(prompt.contains("https://github.com/login/device"));
        assert!(
            prompt.contains("only on that page"),
            "`07-security.md`'s phishing control requires the copy to say the code is only \
             ever entered on GitHub's own domain"
        );
        assert_eq!(
            prompt.matches("http").count(),
            1,
            "the prompt must offer exactly one URL. A second one is a second place a user \
             might type the code: {prompt}"
        );
    }

    // -- the state taxonomy ------------------------------------------------

    /// The four states `f1` requires, plus the fifth that keeps an offline host
    /// from being told to sign in again, must all reach different exit codes.
    #[test]
    fn every_credential_state_reports_itself_distinctly() {
        let states = [
            CredentialState::NotAuthenticated,
            CredentialState::Revoked,
            CredentialState::LockedOut {
                retry_after_secs: 60,
            },
            CredentialState::Unreachable {
                detail: "GitHub was unreachable".to_string(),
            },
        ];
        let mut codes = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for state in &states {
            let class = state
                .failure()
                .expect("only `authenticated` is a success state");
            assert!(
                codes.insert(class.code()),
                "{} shares an exit code with another state, so a script cannot tell them \
                 apart -- and `03-control-flows.md` flow 4.3 requires the lockout to be \
                 reported distinctly from `authentication_failed`",
                state.as_str()
            );
            assert!(names.insert(state.as_str()));
        }
        assert_eq!(codes.len(), states.len());
        assert_eq!(names.len(), states.len());
    }

    /// Each state's explanation must be its own, or two states are one state
    /// wearing different labels.
    #[test]
    fn each_state_explains_itself_in_its_own_words() {
        let states = [
            CredentialState::NotAuthenticated,
            CredentialState::Revoked,
            CredentialState::LockedOut {
                retry_after_secs: 60,
            },
            CredentialState::Unreachable {
                detail: "GitHub was unreachable".to_string(),
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for state in &states {
            let rendered = text(|out| write_state_explanation(out, Styling::plain(), state, false));
            assert!(
                seen.insert(rendered.clone()),
                "{} renders the same explanation as an earlier state",
                state.as_str()
            );
        }

        let unreachable = text(|out| {
            write_state_explanation(
                out,
                Styling::plain(),
                &CredentialState::Unreachable {
                    detail: "GitHub was unreachable".to_string(),
                },
                false,
            )
        });
        assert!(
            unreachable.contains("may be perfectly good"),
            "an offline host must not be told its credential is bad: {unreachable}"
        );
    }

    #[test]
    fn a_lockout_is_never_remedied_by_signing_in_again() {
        let state = CredentialState::LockedOut {
            retry_after_secs: 90,
        };
        let remedy = state.remedy();
        assert!(
            !remedy.contains("auth login"),
            "`03-control-flows.md` flow 4.3: a lockout is not a permissions change and not a \
             bad credential. Telling the operator to re-authenticate during one extends it. \
             Got: {remedy}"
        );
        assert!(remedy.contains("wait"), "got: {remedy}");

        let explanation = text(|out| write_state_explanation(out, Styling::plain(), &state, false));
        assert!(
            explanation.contains("nothing wrong with the token itself"),
            "got: {explanation}"
        );
    }

    #[test]
    fn a_declined_login_and_an_expired_code_are_different_answers() {
        let declined = device_flow_failure(&DeviceFlowError::AccessDenied);
        assert_eq!(declined.class(), Failure::AuthenticationDeclined);
        let expired = device_flow_failure(&DeviceFlowError::Expired);
        assert_eq!(expired.class(), Failure::AuthenticationExpired);
        assert_ne!(
            declined.class().code(),
            expired.class().code(),
            "`c2` documents these as different answers -- retrying a refusal re-prompts \
             somebody who already said no, while an expired code simply needs a new login -- \
             so a script has to be able to tell them apart"
        );
    }

    /// The phishing control must not be reported as an ordinary decode failure:
    /// an operator who sees it needs to know their network is doing something.
    #[test]
    fn an_untrusted_verification_page_is_reported_as_an_interception() {
        let error = device_flow_failure(&DeviceFlowError::UntrustedVerificationUri {
            origin: "https://github.example.com".to_string(),
        });
        assert_eq!(error.class(), Failure::UnusableResponse);
        assert!(error.message().contains("interception"), "{error}");
        assert!(
            error.message().contains("not been shown"),
            "the message must say the code was withheld: {error}"
        );
    }

    /// The rule every failure mapper in this crate obeys: name the command that
    /// fixes it, or say plainly that none does — and never both, and never
    /// neither.
    ///
    /// Checked as an exact bi-implication against [`NO_OPERATOR_REMEDY`]. An
    /// earlier version was a disjunction that accepted the substring
    /// `"Nothing was stored."` as evidence that no remedy exists, which several
    /// arms emit *alongside* a remedy — so it was satisfiable by copy saying
    /// nothing about what to do next, which is the property it claims to
    /// enforce.
    fn assert_says_what_to_do_next(error: &CliError, what: &str) {
        assert_eq!(
            error.remedy().is_some(),
            !error.message().contains(NO_OPERATOR_REMEDY),
            "{what}: `{}` must either name the command that fixes it or say plainly, in \
             the words of NO_OPERATOR_REMEDY, that none does -- and never both. remedy: \
             {:?}",
            error.message(),
            error.remedy()
        );
        assert!(
            !error.message().is_empty() && error.message().len() < 500,
            "{what}: one screenful, not a stack trace: {}",
            error.message()
        );
    }

    /// Both halves of the rule have to be exercised by the cases below, or one
    /// of them is asserted by nothing at all.
    fn assert_both_halves_were_seen(errors: &[CliError], what: &str) {
        let with_remedy = errors.iter().filter(|e| e.remedy().is_some()).count();
        let without = errors.len() - with_remedy;
        assert!(
            with_remedy > 0 && without > 0,
            "{what}: both halves of the rule must be exercised: {with_remedy} with a \
             remedy, {without} without"
        );
    }

    #[test]
    fn every_device_flow_failure_says_what_to_do_next() {
        let cases = [
            DeviceFlowError::AccessDenied,
            DeviceFlowError::Expired,
            DeviceFlowError::IncorrectDeviceCode,
            DeviceFlowError::AppMisconfigured {
                code: "device_flow_disabled".to_string(),
            },
            DeviceFlowError::Unexpected {
                code: "surprise".to_string(),
            },
            DeviceFlowError::UntrustedVerificationUri {
                origin: "https://not-github.example".to_string(),
            },
            DeviceFlowError::Status {
                status: 502,
                stage: "device code request",
            },
            DeviceFlowError::Malformed {
                what: "a verification URL",
                value: "::".to_string(),
            },
        ];
        let errors: Vec<CliError> = cases.iter().map(device_flow_failure).collect();
        for error in &errors {
            assert_says_what_to_do_next(error, "device_flow_failure");
        }
        assert_both_halves_were_seen(&errors, "device_flow_failure");
    }

    /// The sibling mapper, which had no test at all.
    ///
    /// `device_flow_failure` was tightened and `github_failure` — one function
    /// below it, reached by `auth status` on every run — was left with two arms
    /// carrying neither a remedy nor the phrase. Fixing the assertion in one
    /// mapper and not looking at the other is how that survived, so this exists
    /// as much to keep the pair together as to check today's arms.
    ///
    /// `GithubError::Transport` is absent because it cannot be constructed
    /// here: it wraps a `reqwest::Error`, `reqwest` is not a dependency of this
    /// crate, and the type has no public constructor. Its remedy is covered
    /// end to end instead, by
    /// `auth_states.rs::an_unreachable_github_is_not_reported_as_a_bad_credential`,
    /// which drives the real binary at a dead port and asserts on what it
    /// prints.
    #[test]
    fn every_github_failure_says_what_to_do_next() {
        use runner_manager_github::{ConfigError, HeaderMap};

        let decode_error =
            serde_json::from_str::<u32>("not a number").expect_err("a deliberate decode failure");
        let cases = [
            GithubError::AuthenticationFailed,
            GithubError::AuthenticationLockout {
                retry_after: Duration::from_secs(60),
            },
            GithubError::Forbidden {
                method: "GET".to_string(),
                path: "/user/installations".to_string(),
                message: Some("Resource not accessible by integration".to_string()),
                headers: Box::new(HeaderMap::new()),
            },
            GithubError::Status {
                status: 500,
                method: "GET".to_string(),
                path: "/user/installations".to_string(),
                message: None,
                headers: Box::new(HeaderMap::new()),
            },
            GithubError::Decode {
                what: "an installations",
                expected: "a page",
                source: decode_error,
            },
            GithubError::Malformed {
                what: "a repository full_name",
                value: "not/a/slug".to_string(),
            },
            GithubError::Config(ConfigError::Empty { what: "client_id" }),
        ];
        let errors: Vec<CliError> = cases.iter().map(github_failure).collect();
        for error in &errors {
            assert_says_what_to_do_next(error, "github_failure");
        }
        assert_both_halves_were_seen(&errors, "github_failure");
    }

    /// The registration this build carries, and the failure it no longer takes.
    ///
    /// Until Phase 0 of the rollout landed on 2026-08-24 this asserted the
    /// opposite: that `app_registration` FAILED, because no App existed and a
    /// build could only say so. Now that one does, the reachable half of the
    /// property is that a stock build resolves it — a released binary whose
    /// `auth login` reported `AppNotPublished` would be unusable for everyone
    /// who is not setting the test-seam overrides.
    ///
    /// The other half — that `AppNotPublished` says plainly that no command
    /// fixes it, which is the reason [`NO_OPERATOR_REMEDY`] lives in `mod.rs`
    /// rather than here — is exercised below against the error itself, since
    /// no context can produce it any more.
    #[test]
    fn a_stock_build_carries_the_published_app_registration() {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let mut discarded = Vec::new();
        let context = Context::resolve(Some(temporary.path()), &mut discarded)
            .expect("a context rooted at a temporary directory");

        // The environment overrides are a test seam, and one of them being set
        // in a developer's shell would make this pass while a shipped binary
        // failed. Skip rather than assert a value this process did not compile
        // in: `no_plausible_client_id_is_compiled_in` is what pins the
        // constants themselves.
        if std::env::var(crate::cli::CLIENT_ID_VARIABLE).is_ok()
            || std::env::var(crate::cli::APP_SLUG_VARIABLE).is_ok()
        {
            eprintln!(
                "SKIPPED: {} or {} is set, so this process is not a stock build",
                crate::cli::CLIENT_ID_VARIABLE,
                crate::cli::APP_SLUG_VARIABLE
            );
            return;
        }

        let registration = context
            .app_registration()
            .expect("a stock build carries the published App registration");
        assert_eq!(registration.client_id(), crate::cli::PUBLISHED_CLIENT_ID);
        assert_eq!(registration.slug(), crate::cli::PUBLISHED_APP_SLUG);
    }

    /// A build with no registration is a build problem, and the message has to
    /// say so: no command an operator types publishes a GitHub App.
    #[test]
    fn a_missing_app_registration_says_that_no_command_fixes_it() {
        let error = CliError::new(
            Failure::AppNotPublished,
            format!(
                "this build carries no published GitHub App registration, so there is \
                 nothing to sign in to. {NO_OPERATOR_REMEDY}."
            ),
        );
        assert_eq!(error.class(), Failure::AppNotPublished);
        assert_says_what_to_do_next(&error, "Context::app_registration");
        assert!(
            error.remedy().is_none(),
            "there is no operator command that publishes a GitHub App: {error}"
        );
    }

    // -- logout ------------------------------------------------------------

    /// The notice `auth logout` owes, asserted against the function the command
    /// actually calls rather than against a copy of its text.
    #[test]
    fn logout_states_that_the_authoritative_revocation_is_elsewhere() {
        let notice = text(write_revocation_notice);
        assert!(notice.contains(REVOCATION_HEADLINE), "got: {notice}");
        assert!(
            notice.contains("still valid at GitHub"),
            "an operator must not read a local purge as a revocation: {notice}"
        );
        assert!(
            notice.contains("https://github.com/settings/installations"),
            "the notice must name where the revocation is actually done: {notice}"
        );
    }
}
