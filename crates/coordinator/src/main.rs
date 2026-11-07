//! `runner-manager-coordinator`: the server, and its local admin commands.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use chrono::Utc;
use clap::{Parser, Subcommand};
use runner_manager_coordinator::github_app::{AppKey, GithubApp};
use runner_manager_coordinator::server::{AppState, Config, serve};
use runner_manager_coordinator::stats::{self, StatsConfig, Weights};
use runner_manager_coordinator::store::{HostRecord, Store};
use runner_manager_coordinator::sweep::{self, Sweeper};
use runner_manager_coordinator_protocol::CoordinatorUrl;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;

/// The shortest webhook secret accepted.
const MIN_SECRET_LEN: usize = 16;

/// Version of every `--json` document this binary prints.
const JSON_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Parser)]
#[command(name = "runner-manager-coordinator", version, about)]
struct Cli {
    /// The SQLite database the server and the admin commands share.
    #[arg(
        long,
        env = "COORDINATOR_DB",
        default_value = "coordinator.db",
        global = true
    )]
    db: PathBuf,
    /// Samples kept per job key for the job weight statistics.
    #[arg(long, env = "COORDINATOR_STATS_SAMPLES", default_value_t = 30, value_parser = clap::value_parser!(u32).range(1..=1000), global = true)]
    stats_samples: u32,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the server (plain HTTP; put a TLS proxy in front).
    ///
    /// The webhook secret is read from COORDINATOR_WEBHOOK_SECRET_FILE or
    /// COORDINATOR_WEBHOOK_SECRET, never from an argument. With a GitHub App
    /// id and its private key (COORDINATOR_GITHUB_APP_PRIVATE_KEY_FILE or
    /// COORDINATOR_GITHUB_APP_PRIVATE_KEY, never an argument) the server also
    /// runs the reconciliation sweep.
    Serve {
        #[arg(long, env = "COORDINATOR_LISTEN", default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// The public https URL hosts join, e.g. https://runners.example.com.
        #[arg(long, env = "COORDINATOR_PUBLIC_URL")]
        public_url: String,
        /// Trust the right-most X-Forwarded-For entry (only behind the proxy).
        #[arg(long, env = "COORDINATOR_TRUST_FORWARDED_FOR")]
        trust_forwarded_for: bool,
        /// The GitHub App whose installations the reconciliation sweep reads.
        #[arg(long, env = "COORDINATOR_GITHUB_APP_ID")]
        github_app_id: Option<u64>,
        /// How often the sweep reads the hosts' queues: 30s at least, 2m by
        /// default.
        #[arg(long, env = "COORDINATOR_RECONCILE_INTERVAL", default_value = "2m", value_parser = parse_reconcile_interval)]
        reconcile_interval: Duration,
        /// The GitHub REST API, for GitHub Enterprise Server.
        #[arg(long, env = "COORDINATOR_GITHUB_API_URL", default_value = runner_manager_github::GITHUB_API_BASE)]
        github_api_url: url::Url,
        /// The memory a pool job of a repository never measured is assumed
        /// to need: 2GiB, 512MiB.
        #[arg(long, env = "COORDINATOR_DEFAULT_JOB_RAM", default_value = "2GiB", value_parser = parse_bytes)]
        default_job_ram: u64,
        /// Free memory a host must keep beyond a job's estimate to be placed
        /// on.
        #[arg(long, env = "COORDINATOR_RAM_MARGIN", default_value = "512MiB", value_parser = parse_bytes)]
        ram_margin: u64,
        /// The placement score's weights:
        /// cache=4,headroom=2,speed=1,bigfit=1.5 (any subset).
        #[arg(long, env = "COORDINATOR_PLACEMENT_WEIGHTS", default_value = "", value_parser = parse_weights)]
        placement_weights: Weights,
    },
    /// The job weight statistics: heaviest jobs, hosts, recent placements.
    Stats {
        #[arg(long)]
        json: bool,
    },
    /// Issue a one-time code that enrolls one host.
    Invite {
        /// The name the host will have here.
        #[arg(long)]
        name: String,
        /// How long the code stays usable, 1 minute to 7 days: 15m, 2h, 1d.
        #[arg(long, default_value = "15m", value_parser = parse_ttl)]
        ttl: Duration,
    },
    /// Enrolled hosts.
    Hosts {
        #[command(subcommand)]
        command: HostsCommand,
    },
}

#[derive(Debug, Subcommand)]
enum HostsCommand {
    /// Every enrolled host, revoked ones included.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Revoke a host by id or name; a running server closes its live
    /// connection within a second.
    Revoke { host: String },
}

fn parse_ttl(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number
        .parse()
        .map_err(|_| format!("`{text}` is not a duration; write it as 15m, 2h or 1d"))?;
    let seconds = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => {
            return Err(format!(
                "`{text}` is not a duration; write it as 15m, 2h or 1d"
            ));
        }
    };
    Ok(Duration::from_secs(number.saturating_mul(seconds)))
}

fn parse_reconcile_interval(text: &str) -> Result<Duration, String> {
    let interval = parse_ttl(text)?;
    if interval < sweep::MIN_INTERVAL {
        return Err(format!(
            "the reconciliation interval must be at least {}s",
            sweep::MIN_INTERVAL.as_secs()
        ));
    }
    Ok(interval)
}

/// A memory size: `2GiB`, `512MiB`, `1G`, or bytes.
fn parse_bytes(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number
        .parse()
        .map_err(|_| format!("`{text}` is not a size; write it as 2GiB or 512MiB"))?;
    let shift = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 0,
        "k" | "kib" | "kb" => 10,
        "m" | "mib" | "mb" => 20,
        "g" | "gib" | "gb" => 30,
        _ => {
            return Err(format!(
                "`{text}` is not a size; write it as 2GiB or 512MiB"
            ));
        }
    };
    number
        .checked_mul(1 << shift)
        .ok_or_else(|| format!("`{text}` is too large"))
}

/// `cache=4,headroom=2,speed=1,bigfit=1.5`: any subset, the rest default.
fn parse_weights(text: &str) -> Result<Weights, String> {
    let mut weights = Weights::default();
    for part in text
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (name, value) = part
            .split_once('=')
            .ok_or_else(|| format!("`{part}` is not name=value"))?;
        let value: f64 = value
            .trim()
            .parse()
            .ok()
            .filter(|value: &f64| value.is_finite() && (0.0..=100.0).contains(value))
            .ok_or_else(|| format!("`{part}`: a weight is a number from 0 to 100"))?;
        match name.trim() {
            "cache" => weights.cache = value,
            "headroom" => weights.headroom = value,
            "speed" => weights.speed = value,
            "bigfit" => weights.bigfit = value,
            other => {
                return Err(format!(
                    "`{other}` is not a weight; use cache, headroom, speed or bigfit"
                ));
            }
        }
    }
    Ok(weights)
}

/// The App's private key, from a file or the environment; `None` when
/// neither is set.
fn github_app_key() -> anyhow::Result<Option<SecretString>> {
    if let Some(path) = std::env::var_os("COORDINATOR_GITHUB_APP_PRIVATE_KEY_FILE") {
        return std::fs::read_to_string(&path)
            .map(|text| Some(SecretString::from(text)))
            .context("cannot read the file COORDINATOR_GITHUB_APP_PRIVATE_KEY_FILE names");
    }
    Ok(std::env::var("COORDINATOR_GITHUB_APP_PRIVATE_KEY")
        .ok()
        .map(SecretString::from))
}

/// The GitHub App, when one is configured.
fn github_app(id: Option<u64>, api: url::Url) -> anyhow::Result<Option<GithubApp>> {
    let app = match (id, github_app_key()?) {
        (None, None) => return Ok(None),
        (Some(id), Some(pem)) => AppKey::from_pem(id, &pem)?,
        (Some(_), None) => bail!(
            "COORDINATOR_GITHUB_APP_ID is set but no private key: set \
             COORDINATOR_GITHUB_APP_PRIVATE_KEY_FILE (preferred) or COORDINATOR_GITHUB_APP_PRIVATE_KEY"
        ),
        (None, Some(_)) => {
            bail!("a GitHub App private key is set but COORDINATOR_GITHUB_APP_ID is not")
        }
    };
    let web = url::Url::parse(runner_manager_github::GITHUB_WEB_BASE)?;
    Ok(Some(GithubApp::new(
        app,
        runner_manager_github::Endpoints::new(api, web),
        Arc::new(runner_manager_domain::model::SystemClock),
    )?))
}

fn webhook_secret() -> anyhow::Result<SecretString> {
    let secret = if let Some(path) = std::env::var_os("COORDINATOR_WEBHOOK_SECRET_FILE") {
        std::fs::read_to_string(&path)
            .map(|text| text.trim().to_string())
            .context("cannot read the file COORDINATOR_WEBHOOK_SECRET_FILE names")?
    } else if let Ok(value) = std::env::var("COORDINATOR_WEBHOOK_SECRET") {
        value.trim().to_string()
    } else {
        bail!("set COORDINATOR_WEBHOOK_SECRET_FILE (preferred) or COORDINATOR_WEBHOOK_SECRET");
    };
    if secret.len() < MIN_SECRET_LEN {
        bail!("the webhook secret must be at least {MIN_SECRET_LEN} characters");
    }
    Ok(SecretString::from(secret))
}

#[derive(Serialize)]
struct HostsDocument<'a> {
    schema_version: u32,
    hosts: &'a [HostRecord],
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    match cli.command {
        Command::Serve {
            listen,
            public_url,
            trust_forwarded_for,
            github_app_id,
            reconcile_interval,
            github_api_url,
            default_job_ram,
            ram_margin,
            placement_weights,
        } => {
            let origin = CoordinatorUrl::parse(&public_url)
                .context("COORDINATOR_PUBLIC_URL is not a usable https URL")?
                .origin();
            let mut config = Config::new(origin, webhook_secret()?);
            config.trust_forwarded_for = trust_forwarded_for;
            config.stats = StatsConfig {
                samples_per_job: cli.stats_samples,
                default_job_ram,
                ram_margin,
                weights: placement_weights,
                ..StatsConfig::default()
            };
            let app = github_app(github_app_id, github_api_url)?;
            let store = Store::open(&cli.db)?;
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind(listen)
                    .await
                    .with_context(|| format!("cannot listen on {listen}"))?;
                let state = AppState::new(config, store);
                if let Some(app) = app {
                    tracing::info!(
                        app_id = github_app_id.unwrap_or_default(),
                        interval_secs = reconcile_interval.as_secs(),
                        "the reconciliation sweep runs"
                    );
                    tokio::spawn(
                        Sweeper::new(
                            reconcile_interval,
                            Box::new(app),
                            Arc::clone(&state.registry),
                        )
                        .with_placement(Arc::clone(&state.placement))
                        .run(),
                    );
                } else {
                    tracing::info!(
                        "no GitHub App is configured: webhooks wake hosts, and no reconciliation \
                         sweep runs"
                    );
                }
                tracing::info!(%listen, "coordinator listening");
                serve(listener, state, shutdown_signal()).await?;
                anyhow::Ok(())
            })?;
        }
        Command::Invite { name, ttl } => {
            let invite = Store::open(&cli.db)?.create_invite(&name, ttl, Utc::now())?;
            writeln!(
                out,
                "invite for `{}`, usable once until {}:\n\n  {}\n\non the host:\n\n  runner-manager coordinator join <public URL> --code {}",
                invite.name,
                invite.expires_at.to_rfc3339(),
                invite.code.expose_secret(),
                invite.code.expose_secret()
            )?;
        }
        Command::Stats { json } => {
            let store = Store::open(&cli.db)?;
            let config = StatsConfig {
                samples_per_job: cli.stats_samples,
                ..StatsConfig::default()
            };
            let report = stats::report(&store, &config, Utc::now())?;
            if json {
                #[derive(Serialize)]
                struct StatsDocument<'a> {
                    schema_version: u32,
                    #[serde(flatten)]
                    report: &'a runner_manager_coordinator_protocol::StatsReport,
                }
                serde_json::to_writer_pretty(
                    &mut out,
                    &StatsDocument {
                        schema_version: JSON_SCHEMA_VERSION,
                        report: &report,
                    },
                )?;
                writeln!(out)?;
            } else {
                let mut text = String::new();
                report.render(&mut text)?;
                write!(out, "{text}")?;
            }
        }
        Command::Hosts { command } => {
            let store = Store::open(&cli.db)?;
            match command {
                HostsCommand::List { json } => {
                    let hosts = store.hosts()?;
                    if json {
                        serde_json::to_writer_pretty(
                            &mut out,
                            &HostsDocument {
                                schema_version: JSON_SCHEMA_VERSION,
                                hosts: &hosts,
                            },
                        )?;
                        writeln!(out)?;
                    } else if hosts.is_empty() {
                        writeln!(out, "no host has enrolled")?;
                    } else {
                        for host in hosts {
                            let state = if host.is_active() {
                                "active"
                            } else {
                                "revoked"
                            };
                            let seen = host
                                .last_seen_at
                                .map_or_else(|| "never".to_string(), |at| at.to_rfc3339());
                            writeln!(
                                out,
                                "{}  {:<20} {:<8} host {:<24} last seen {seen}",
                                host.id, host.name, state, host.hostname
                            )?;
                        }
                    }
                }
                HostsCommand::Revoke { host } => {
                    let record = store.revoke(&host, Utc::now())?;
                    writeln!(out, "revoked {} ({})", record.name, record.id)?;
                }
            }
        }
    }
    Ok(())
}

/// Ctrl-C, or SIGTERM: what `docker stop` and systemd send. As PID 1 in the
/// container the process has no default SIGTERM action, so without this a
/// stop waits out Docker's grace period and ends in SIGKILL.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetimes_parse_in_the_forms_an_operator_writes() {
        assert_eq!(parse_ttl("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_ttl("2h"), Ok(Duration::from_secs(7200)));
        assert_eq!(parse_ttl("90"), Ok(Duration::from_secs(90)));
        assert!(parse_ttl("soon").is_err());
        assert!(parse_ttl("5y").is_err());
        assert_eq!(parse_reconcile_interval("2m"), Ok(Duration::from_secs(120)));
        assert!(parse_reconcile_interval("29s").is_err());
    }

    #[test]
    fn sizes_and_weights_parse_in_the_forms_an_operator_writes() {
        assert_eq!(parse_bytes("2GiB"), Ok(2 << 30));
        assert_eq!(parse_bytes("512MiB"), Ok(512 << 20));
        assert_eq!(parse_bytes("1g"), Ok(1 << 30));
        assert_eq!(parse_bytes("4096"), Ok(4096));
        assert!(parse_bytes("lots").is_err() && parse_bytes("2TiB").is_err());
        assert_eq!(parse_weights(""), Ok(Weights::default()));
        let weights = parse_weights("cache=0, bigfit=3").expect("parses");
        assert_eq!((weights.cache, weights.bigfit), (0.0, 3.0));
        assert_eq!(weights.headroom, Weights::default().headroom);
        assert!(parse_weights("gpu=1").is_err());
        assert!(parse_weights("cache=-1").is_err());
        assert!(parse_weights("cache").is_err());
    }

    #[test]
    fn the_cli_parses() {
        use clap::CommandFactory as _;
        Cli::command().debug_assert();
    }
}
