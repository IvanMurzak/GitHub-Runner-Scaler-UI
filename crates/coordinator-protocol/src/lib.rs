//! The wire contract between `runner-manager` and its optional coordinator.
//!
//! Stage 1 of `.taskflow/2026-11-07-coordinator-server`: hosts connect out to
//! the coordinator over a WebSocket, prove who they are with an Ed25519
//! signature over a server nonce, describe themselves (`hello`), report their
//! load (`heartbeat`), and are told to poll a target now (`wake`) when GitHub
//! delivers a queued `workflow_job`. The coordinator advises; the host decides.
//!
//! # Versioning
//!
//! Every message is one JSON object tagged by `type`. [`PROTOCOL_VERSION`] is
//! carried by the server's `challenge`, the host's `auth` and `hello`, and the
//! enrollment request; a peer refuses a version it does not speak rather than
//! guessing. Within one version, fields may be **added** but never removed or
//! retyped: unknown fields are ignored on decode, and an unknown message type
//! decodes as [`HostMessage::Unknown`] / [`ServerMessage::Unknown`] so that an
//! older peer skips it instead of dropping the connection.
//!
//! # What never crosses this wire
//!
//! GitHub tokens, JIT configurations, job logs, the host's private key, and
//! the webhook secret. A `wake` carries a target, a repository name, a reason
//! and GitHub's delivery id — nothing a host must trust beyond "poll now".

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The protocol this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Domain separation for the connection signature. A signature made for this
/// purpose can never be replayed as anything else, and vice versa.
pub const AUTH_CONTEXT: &[u8] = b"runner-manager-coordinator/v1/host-auth";

/// Bytes of server randomness in every challenge.
pub const NONCE_LEN: usize = 32;

/// The largest single WebSocket message either side accepts.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// WebSocket close code: authentication failed (unknown, revoked or wrong key).
pub const CLOSE_UNAUTHORIZED: u16 = 4401;
/// WebSocket close code: the peer speaks a protocol version this one does not.
pub const CLOSE_UNSUPPORTED_VERSION: u16 = 4400;
/// WebSocket close code: a newer connection for the same host replaced this one.
pub const CLOSE_REPLACED: u16 = 4409;

/// The coordinator's paths, relative to its public origin.
pub const CONNECT_PATH: &str = "/connect";
pub const ENROLL_PATH: &str = "/enroll";
pub const WEBHOOK_PATH: &str = "/webhook";
pub const HEALTH_PATH: &str = "/healthz";

/// Why a message or a URL was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("the coordinator URL is not a URL")]
    InvalidUrl,
    #[error("the coordinator URL must use https (http is allowed for loopback only)")]
    InsecureUrl,
    #[error("the message is not valid protocol JSON")]
    Malformed,
    #[error("the key is not a valid Ed25519 key")]
    InvalidKey,
    #[error("the signature is not a valid Ed25519 signature")]
    InvalidSignature,
}

// ---------------------------------------------------------------------------
// Targets, hello and heartbeat
// ---------------------------------------------------------------------------

/// Whether a target is one repository or a whole organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetScope {
    Repo,
    Org,
}

/// A target as both sides name it: `owner/name` for a repository, the login
/// for an organization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetRef {
    pub scope: TargetScope,
    pub name: String,
}

impl TargetRef {
    /// Whether this target covers `repository` (`owner/name`), compared the
    /// way GitHub compares names: case-insensitively.
    #[must_use]
    pub fn covers(&self, repository: &str) -> bool {
        match self.scope {
            TargetScope::Repo => self.name.eq_ignore_ascii_case(repository),
            TargetScope::Org => repository
                .split_once('/')
                .is_some_and(|(owner, _)| owner.eq_ignore_ascii_case(&self.name)),
        }
    }
}

impl fmt::Display for TargetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scope {
            TargetScope::Repo => write!(f, "repo:{}", self.name),
            TargetScope::Org => write!(f, "org:{}", self.name),
        }
    }
}

/// One runner profile a host serves a target with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    /// The labels the profile's runners register with.
    pub labels: Vec<String>,
    /// Whether the profile may start runners now.
    pub enabled: bool,
}

/// A target and the profiles that serve it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub scope: TargetScope,
    pub name: String,
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

impl Target {
    #[must_use]
    pub fn reference(&self) -> TargetRef {
        TargetRef {
            scope: self.scope,
            name: self.name.clone(),
        }
    }
}

/// What a host says about itself once authenticated (D8: hardware is
/// reported, never configured on the coordinator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_version: u32,
    pub host_id: String,
    /// `windows`, `macos`, `linux`.
    pub os: String,
    /// `x64`, `arm64`.
    pub arch: String,
    pub cores: u32,
    #[serde(default)]
    pub ram_bytes: Option<u64>,
    #[serde(default)]
    pub disk_free_bytes: Option<u64>,
    #[serde(default)]
    pub targets: Vec<Target>,
}

/// A host's periodic load report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Heartbeat {
    pub free_slots: u32,
    pub busy_slots: u32,
    pub cpu_load_percent: Option<u32>,
    pub free_ram_bytes: Option<u64>,
    /// A required `host doctor` check fails; the host starts no runner.
    pub unfit: bool,
    /// The daemon is draining for a shutdown, upgrade or reload.
    pub draining: bool,
}

// ---------------------------------------------------------------------------
// Wake
// ---------------------------------------------------------------------------

/// Why the coordinator woke a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeReason {
    /// GitHub queued a job the host advertised a matching profile for.
    JobQueued,
    /// A reason this build does not know. Still a wake.
    #[serde(other)]
    Other,
}

/// "Poll this target now." Nothing more: the host computes demand itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wake {
    pub target: TargetRef,
    /// The repository the event came from, `owner/name`.
    pub repository: String,
    pub reason: WakeReason,
    /// GitHub's `X-GitHub-Delivery`, for correlating logs on both sides.
    pub delivery_id: String,
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

/// Everything a host sends over the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    /// The answer to [`ServerMessage::Challenge`].
    Auth {
        protocol_version: u32,
        host_id: String,
        /// Base64 Ed25519 signature over [`auth_message`].
        signature: String,
    },
    Hello(Hello),
    Heartbeat(Heartbeat),
    #[serde(other)]
    Unknown,
}

/// Everything the coordinator sends over the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// The first message on every connection.
    Challenge {
        protocol_version: u32,
        /// Base64 of [`NONCE_LEN`] random bytes.
        nonce: String,
    },
    /// Authentication succeeded.
    Welcome {
        protocol_version: u32,
        heartbeat_interval_secs: u32,
    },
    Wake(Wake),
    #[serde(other)]
    Unknown,
}

macro_rules! json_codec {
    ($ty:ty) => {
        impl $ty {
            /// The message as one JSON text frame.
            #[must_use]
            pub fn encode(&self) -> String {
                serde_json::to_string(self).expect("protocol messages always serialize")
            }

            /// Parses one frame.
            ///
            /// # Errors
            /// [`ProtocolError::Malformed`]: the error deliberately carries
            /// nothing from the frame, so it can be logged.
            pub fn decode(text: &str) -> Result<Self, ProtocolError> {
                if text.len() > MAX_MESSAGE_BYTES {
                    return Err(ProtocolError::Malformed);
                }
                serde_json::from_str(text).map_err(|_| ProtocolError::Malformed)
            }
        }
    };
}

json_codec!(HostMessage);
json_codec!(ServerMessage);

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

/// `POST /enroll`: spend a one-time code to register this host's public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub protocol_version: u32,
    pub code: String,
    /// The machine's own name, as the host reports it.
    pub hostname: String,
    /// Base64 of the 32-byte Ed25519 public key.
    pub public_key: String,
}

/// The coordinator's answer to a successful enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub protocol_version: u32,
    pub host_id: String,
    /// The name the coordinator's operator gave this host at `invite`.
    pub name: String,
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

/// A coordinator's address, normalised to its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorUrl {
    origin: url::Url,
}

impl CoordinatorUrl {
    /// Parses what an operator typed. Only the origin is kept: a path,
    /// query or fragment is dropped.
    ///
    /// # Errors
    /// Not a URL, not `https`, or `http` to anything but loopback.
    pub fn parse(raw: &str) -> Result<Self, ProtocolError> {
        let parsed = url::Url::parse(raw.trim()).map_err(|_| ProtocolError::InvalidUrl)?;
        let host = parsed.host().ok_or(ProtocolError::InvalidUrl)?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ProtocolError::InvalidUrl);
        }
        match parsed.scheme() {
            "https" => {}
            "http" if is_loopback(&host) => {}
            "http" => return Err(ProtocolError::InsecureUrl),
            _ => return Err(ProtocolError::InvalidUrl),
        }
        let origin = url::Url::parse(&parsed.origin().ascii_serialization())
            .map_err(|_| ProtocolError::InvalidUrl)?;
        Ok(Self { origin })
    }

    /// `scheme://host[:port]`, what the connection signature binds to.
    #[must_use]
    pub fn origin(&self) -> String {
        self.origin.origin().ascii_serialization()
    }

    /// The WebSocket endpoint: `wss://…/connect` (or `ws://` for loopback).
    #[must_use]
    pub fn connect_url(&self) -> String {
        let scheme = if self.origin.scheme() == "https" {
            "wss"
        } else {
            "ws"
        };
        let rest = self
            .origin()
            .split_once("://")
            .map_or(String::new(), |(_, rest)| rest.to_string());
        format!("{scheme}://{rest}{CONNECT_PATH}")
    }

    /// The enrollment endpoint.
    #[must_use]
    pub fn enroll_url(&self) -> String {
        format!("{}{ENROLL_PATH}", self.origin())
    }
}

impl fmt::Display for CoordinatorUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.origin())
    }
}

fn is_loopback(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}

// ---------------------------------------------------------------------------
// Host authentication
// ---------------------------------------------------------------------------

/// The bytes a host signs: `nonce || AUTH_CONTEXT || origin`.
///
/// The nonce is fixed-length, so the concatenation is unambiguous. Binding the
/// origin means a signature a malicious server collects cannot be relayed to
/// a different coordinator.
#[must_use]
pub fn auth_message(nonce: &[u8; NONCE_LEN], origin: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(NONCE_LEN + AUTH_CONTEXT.len() + origin.len());
    message.extend_from_slice(nonce);
    message.extend_from_slice(AUTH_CONTEXT);
    message.extend_from_slice(origin.as_bytes());
    message
}

/// Encodes a nonce for the `challenge` message.
#[must_use]
pub fn encode_nonce(nonce: &[u8; NONCE_LEN]) -> String {
    BASE64.encode(nonce)
}

/// Decodes a `challenge` nonce.
///
/// # Errors
/// [`ProtocolError::Malformed`] when it is not base64 of [`NONCE_LEN`] bytes.
pub fn decode_nonce(text: &str) -> Result<[u8; NONCE_LEN], ProtocolError> {
    BASE64
        .decode(text)
        .ok()
        .and_then(|bytes| <[u8; NONCE_LEN]>::try_from(bytes).ok())
        .ok_or(ProtocolError::Malformed)
}

/// Signs a challenge; the result goes in [`HostMessage::Auth`].
#[must_use]
pub fn sign_challenge(key: &SigningKey, nonce: &[u8; NONCE_LEN], origin: &str) -> String {
    BASE64.encode(key.sign(&auth_message(nonce, origin)).to_bytes())
}

/// Whether `signature` is `public_key`'s signature over this challenge.
///
/// Strict verification: rejects weak keys and malleable signatures.
#[must_use]
pub fn verify_challenge(
    public_key: &VerifyingKey,
    nonce: &[u8; NONCE_LEN],
    origin: &str,
    signature: &str,
) -> bool {
    let Ok(bytes) = BASE64.decode(signature) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    public_key
        .verify_strict(&auth_message(nonce, origin), &signature)
        .is_ok()
}

/// A public key as it travels and is stored: base64 of 32 bytes.
#[must_use]
pub fn encode_public_key(key: &VerifyingKey) -> String {
    BASE64.encode(key.as_bytes())
}

/// Parses [`encode_public_key`]'s output, refusing weak keys.
///
/// # Errors
/// [`ProtocolError::InvalidKey`].
pub fn decode_public_key(text: &str) -> Result<VerifyingKey, ProtocolError> {
    let bytes = BASE64.decode(text).map_err(|_| ProtocolError::InvalidKey)?;
    let bytes = <[u8; 32]>::try_from(bytes).map_err(|_| ProtocolError::InvalidKey)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| ProtocolError::InvalidKey)?;
    if key.is_weak() {
        return Err(ProtocolError::InvalidKey);
    }
    Ok(key)
}

/// A private key as the host's secret store holds it: base64 of the 32-byte
/// seed. The caller keeps the result inside a secret type.
#[must_use]
pub fn encode_signing_key(key: &SigningKey) -> String {
    BASE64.encode(key.to_bytes())
}

/// Parses [`encode_signing_key`]'s output.
///
/// # Errors
/// [`ProtocolError::InvalidKey`]; the error carries nothing of the input.
pub fn decode_signing_key(text: &str) -> Result<SigningKey, ProtocolError> {
    let bytes = BASE64
        .decode(text.trim())
        .map_err(|_| ProtocolError::InvalidKey)?;
    let seed = <[u8; 32]>::try_from(bytes).map_err(|_| ProtocolError::InvalidKey)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// A new signing key from 32 bytes of the caller's randomness.
#[must_use]
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub use ed25519_dalek::{SigningKey as HostSigningKey, VerifyingKey as HostPublicKey};

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        signing_key_from_seed(&[byte; 32])
    }

    fn hello() -> Hello {
        Hello {
            protocol_version: PROTOCOL_VERSION,
            host_id: "h1".into(),
            os: "linux".into(),
            arch: "x64".into(),
            cores: 16,
            ram_bytes: Some(64 << 30),
            disk_free_bytes: None,
            targets: vec![Target {
                scope: TargetScope::Repo,
                name: "octo/app".into(),
                profiles: vec![Profile {
                    name: "default".into(),
                    labels: vec!["self-hosted".into(), "linux".into()],
                    enabled: true,
                }],
            }],
        }
    }

    #[test]
    fn every_message_round_trips_with_its_type_tag() {
        let messages = [
            HostMessage::Auth {
                protocol_version: PROTOCOL_VERSION,
                host_id: "h1".into(),
                signature: "c2ln".into(),
            },
            HostMessage::Hello(hello()),
            HostMessage::Heartbeat(Heartbeat {
                free_slots: 2,
                busy_slots: 1,
                cpu_load_percent: Some(40),
                free_ram_bytes: None,
                unfit: false,
                draining: true,
            }),
        ];
        for message in messages {
            let text = message.encode();
            assert!(text.contains("\"type\":"), "{text}");
            assert_eq!(HostMessage::decode(&text).expect("decodes"), message);
        }
        let server = [
            ServerMessage::Challenge {
                protocol_version: PROTOCOL_VERSION,
                nonce: encode_nonce(&[7; NONCE_LEN]),
            },
            ServerMessage::Welcome {
                protocol_version: PROTOCOL_VERSION,
                heartbeat_interval_secs: 15,
            },
            ServerMessage::Wake(Wake {
                target: TargetRef {
                    scope: TargetScope::Org,
                    name: "octo".into(),
                },
                repository: "octo/app".into(),
                reason: WakeReason::JobQueued,
                delivery_id: "d-1".into(),
            }),
        ];
        for message in server {
            assert_eq!(
                ServerMessage::decode(&message.encode()).expect("decodes"),
                message
            );
        }
    }

    #[test]
    fn the_wire_names_are_stable() {
        let text = HostMessage::Heartbeat(Heartbeat::default()).encode();
        assert_eq!(
            text,
            r#"{"type":"heartbeat","free_slots":0,"busy_slots":0,"cpu_load_percent":null,"free_ram_bytes":null,"unfit":false,"draining":false}"#
        );
    }

    #[test]
    fn a_newer_peer_is_tolerated_and_garbage_is_refused() {
        // An added field, and a message type this build has never heard of.
        let with_field = r#"{"type":"heartbeat","free_slots":1,"gpu":"x"}"#;
        assert!(matches!(
            HostMessage::decode(with_field),
            Ok(HostMessage::Heartbeat(Heartbeat { free_slots: 1, .. }))
        ));
        assert_eq!(
            ServerMessage::decode(r#"{"type":"launch","lease_id":"l"}"#),
            Ok(ServerMessage::Unknown)
        );
        let wake = r#"{"type":"wake","target":{"scope":"repo","name":"a/b"},"repository":"a/b","reason":"rebalance","delivery_id":"d"}"#;
        assert!(matches!(
            ServerMessage::decode(wake),
            Ok(ServerMessage::Wake(Wake {
                reason: WakeReason::Other,
                ..
            }))
        ));
        assert_eq!(
            HostMessage::decode("not json"),
            Err(ProtocolError::Malformed)
        );
        let huge = format!(
            r#"{{"type":"heartbeat","x":"{}"}}"#,
            "a".repeat(MAX_MESSAGE_BYTES)
        );
        assert_eq!(HostMessage::decode(&huge), Err(ProtocolError::Malformed));
    }

    #[test]
    fn a_signature_verifies_only_for_its_key_nonce_and_origin() {
        let signer = key(1);
        let nonce = [9; NONCE_LEN];
        let origin = "https://runners.example.com";
        let signature = sign_challenge(&signer, &nonce, origin);
        let public = signer.verifying_key();
        assert!(verify_challenge(&public, &nonce, origin, &signature));
        assert!(!verify_challenge(
            &key(2).verifying_key(),
            &nonce,
            origin,
            &signature
        ));
        assert!(!verify_challenge(
            &public,
            &[8; NONCE_LEN],
            origin,
            &signature
        ));
        assert!(!verify_challenge(
            &public,
            &nonce,
            "https://evil.example.com",
            &signature
        ));
        assert!(!verify_challenge(&public, &nonce, origin, "not base64!"));
    }

    #[test]
    fn keys_round_trip_and_bad_ones_are_refused() {
        let signer = key(3);
        let decoded = decode_signing_key(&encode_signing_key(&signer)).expect("decodes");
        assert_eq!(decoded.to_bytes(), signer.to_bytes());
        let public = decode_public_key(&encode_public_key(&signer.verifying_key())).expect("ok");
        assert_eq!(public, signer.verifying_key());
        assert_eq!(decode_public_key("AAAA"), Err(ProtocolError::InvalidKey));
        // The identity point is a weak key.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            decode_public_key(&BASE64.encode(identity)),
            Err(ProtocolError::InvalidKey)
        );
        assert!(decode_nonce(&encode_nonce(&[1; NONCE_LEN])).is_ok());
        assert!(decode_nonce("AAAA").is_err());
    }

    #[test]
    fn urls_are_normalised_to_their_origin_and_must_be_secure() {
        let url = CoordinatorUrl::parse("https://Runners.Example.com/some/path?x=1").expect("ok");
        assert_eq!(url.origin(), "https://runners.example.com");
        assert_eq!(url.connect_url(), "wss://runners.example.com/connect");
        assert_eq!(url.enroll_url(), "https://runners.example.com/enroll");
        let local = CoordinatorUrl::parse("http://127.0.0.1:8080").expect("loopback");
        assert_eq!(local.connect_url(), "ws://127.0.0.1:8080/connect");
        assert_eq!(
            CoordinatorUrl::parse("http://runners.example.com"),
            Err(ProtocolError::InsecureUrl)
        );
        assert_eq!(
            CoordinatorUrl::parse("ftp://x"),
            Err(ProtocolError::InvalidUrl)
        );
        assert!(CoordinatorUrl::parse("https://user:pw@x.example").is_err());
    }

    #[test]
    fn a_target_covers_its_repository_or_its_organizations_repositories() {
        let repo = TargetRef {
            scope: TargetScope::Repo,
            name: "Octo/App".into(),
        };
        assert!(repo.covers("octo/app"));
        assert!(!repo.covers("octo/other"));
        let org = TargetRef {
            scope: TargetScope::Org,
            name: "OCTO".into(),
        };
        assert!(org.covers("octo/anything"));
        assert!(!org.covers("octopus/app"));
        assert!(!org.covers("octo"));
    }
}
