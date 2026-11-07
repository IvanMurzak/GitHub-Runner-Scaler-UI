//! The coordinator's own GitHub identity: the owner's personal GitHub App
//! (D7), for the reconciliation sweep.
//!
//! An App authenticates in two steps. A short JWT signed with the App's RSA
//! private key (RS256, at most ten minutes long) proves "I am App N"; with it
//! the coordinator lists the App's installations and mints an **installation
//! token** per installation, which lasts one hour and carries the App's
//! permissions (Actions: read, Metadata: read) on that installation's
//! repositories. The sweep reads queued runs with installation tokens, one
//! rate-limit bucket per installation, never with a host's credential.
//!
//! Every REST request goes through `runner-manager-github`'s
//! [`AuthenticatedClient`]: the same headers, error taxonomy and traffic
//! accounting the hosts use. Each installation keeps one client for its
//! whole life and is handed a fresh token before the old one expires
//! ([`AuthenticatedClient::replace_credential`]), so its conditional cache
//! and its rate-limit quiet period survive the hourly rotation.
//!
//! # Secrets
//!
//! The private key, every JWT and every installation token live in
//! [`SecretString`]s or in [`RsaKeyPair`], and no type here derives `Debug`
//! over one. Errors carry fixed words and GitHub's status, never a body that
//! could echo a credential.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use reqwest::Method;
use runner_manager_domain::model::{Clock, OwnerRepo, Timestamp};
use runner_manager_github::demand::{DemandGateway, RestDemand};
use runner_manager_github::rest::PER_PAGE;
use runner_manager_github::{
    ApiRequest, AuthenticatedClient, Endpoints, GithubError, MAX_PAGES, UserAccessToken,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;

/// How long a JWT is valid. GitHub's ceiling is ten minutes.
const JWT_LIFETIME: Duration = Duration::from_secs(9 * 60);

/// How far `iat` is back-dated, for clock drift against GitHub's.
const JWT_BACKDATE: Duration = Duration::from_secs(60);

/// An installation token is replaced once less than this is left on it.
pub const TOKEN_REFRESH_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Why the App's credentials or GitHub's answers were unusable.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(
        "the GitHub App private key is not an RSA key in PEM form (PKCS#1 `RSA PRIVATE KEY` \
         or PKCS#8 `PRIVATE KEY`)"
    )]
    InvalidKey,
    #[error("the JWT could not be signed")]
    Signing,
    #[error("the HTTPS client could not be built")]
    Client,
    #[error("GitHub: {0}")]
    Github(#[from] GithubError),
}

// ---------------------------------------------------------------------------
// The App's key and its JWTs
// ---------------------------------------------------------------------------

/// The App id and its private key.
pub struct AppKey {
    app_id: u64,
    key: RsaKeyPair,
}

impl fmt::Debug for AppKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppKey")
            .field("app_id", &self.app_id)
            .field("key", &"[redacted]")
            .finish()
    }
}

impl AppKey {
    /// Parses the key GitHub hands out (`.pem`, PKCS#1) or its PKCS#8 form.
    ///
    /// # Errors
    /// [`AppError::InvalidKey`]; it carries nothing of the input.
    pub fn from_pem(app_id: u64, pem: &SecretString) -> Result<Self, AppError> {
        let text = pem.expose_secret();
        let body: String = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("-----"))
            .collect();
        let der = STANDARD.decode(body).map_err(|_| AppError::InvalidKey)?;
        let key = if text.contains("BEGIN RSA PRIVATE KEY") {
            RsaKeyPair::from_der(&der)
        } else {
            RsaKeyPair::from_pkcs8(&der)
        }
        .map_err(|_| AppError::InvalidKey)?;
        Ok(Self { app_id, key })
    }

    #[must_use]
    pub const fn app_id(&self) -> u64 {
        self.app_id
    }

    /// A JWT for `now`: `iat` a minute back, `exp` nine minutes on, `iss` the
    /// App id.
    ///
    /// # Errors
    /// [`AppError::Signing`].
    pub fn jwt(&self, now: Timestamp) -> Result<SecretString, AppError> {
        let issued = now.timestamp() - secs(JWT_BACKDATE);
        let expires = now.timestamp() + secs(JWT_LIFETIME);
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::json!({ "iat": issued, "exp": expires, "iss": self.app_id.to_string() })
                .to_string(),
        );
        let signing_input = format!("{header}.{claims}");
        let mut signature = vec![0; self.key.public_modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &aws_lc_rs::rand::SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| AppError::Signing)?;
        Ok(SecretString::from(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        )))
    }
}

fn secs(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

// ---------------------------------------------------------------------------
// Installations
// ---------------------------------------------------------------------------

/// One installation of the App, with its own client and token.
pub struct Installation {
    pub id: u64,
    /// The account it is installed on: a user or organization login.
    pub account: String,
    /// `true` when the installation covers every repository of the account
    /// (`repository_selection: all`), so it covers an organization target.
    pub all_repositories: bool,
    /// The repositories it can read, as of the last inventory.
    pub repositories: Vec<OwnerRepo>,
    client: Arc<AuthenticatedClient>,
    demand: Arc<RestDemand>,
    token_expires_at: Timestamp,
}

impl fmt::Debug for Installation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Installation")
            .field("id", &self.id)
            .field("account", &self.account)
            .field("repositories", &self.repositories.len())
            .field("token_expires_at", &self.token_expires_at)
            .finish_non_exhaustive()
    }
}

impl Installation {
    /// The demand reader over this installation's token.
    #[must_use]
    pub fn demand(&self) -> Arc<dyn DemandGateway> {
        Arc::clone(&self.demand) as Arc<dyn DemandGateway>
    }
}

#[derive(Deserialize)]
struct RawInstallation {
    id: u64,
    account: Option<RawAccount>,
    #[serde(default)]
    repository_selection: Option<String>,
    #[serde(default)]
    suspended_at: Option<String>,
}

#[derive(Deserialize)]
struct RawAccount {
    /// Absent for an enterprise account, which no target names.
    #[serde(default)]
    login: Option<String>,
}

#[derive(Deserialize)]
struct RawToken {
    token: String,
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct RawRepositories {
    repositories: Vec<RawRepository>,
}

#[derive(Deserialize)]
struct RawRepository {
    full_name: String,
}

/// The App, its installations, and their tokens.
pub struct GithubApp {
    key: AppKey,
    endpoints: Endpoints,
    http: reqwest::Client,
    clock: Arc<dyn Clock>,
    installations: BTreeMap<u64, Installation>,
}

impl fmt::Debug for GithubApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubApp")
            .field("app_id", &self.key.app_id)
            .field("installations", &self.installations.len())
            .finish_non_exhaustive()
    }
}

impl GithubApp {
    /// # Errors
    /// The HTTP client failing to build.
    pub fn new(key: AppKey, endpoints: Endpoints, clock: Arc<dyn Clock>) -> Result<Self, AppError> {
        let http = reqwest::Client::builder()
            .timeout(runner_manager_github::DEFAULT_REQUEST_TIMEOUT)
            .build()
            .map_err(|_| AppError::Client)?;
        Ok(Self {
            key,
            endpoints,
            http,
            clock,
            installations: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn installations(&self) -> &BTreeMap<u64, Installation> {
        &self.installations
    }

    /// A client authenticated as the App itself, for one round of calls.
    fn app_client(&self) -> Result<AuthenticatedClient, AppError> {
        let jwt = self.key.jwt(self.clock.now())?;
        Ok(AuthenticatedClient::with_http_client(
            self.http.clone(),
            self.endpoints.clone(),
            UserAccessToken::new(jwt),
            Arc::clone(&self.clock),
        ))
    }

    /// Re-reads the installations and the repositories each can read,
    /// minting or refreshing tokens on the way. An installation that is gone
    /// or suspended is dropped with its client.
    ///
    /// # Errors
    /// A failure listing the installations; one installation's failure is
    /// logged and that installation dropped until the next inventory.
    pub async fn refresh_inventory(&mut self) -> Result<(), AppError> {
        let app = self.app_client()?;
        let listed = list_installations(&app).await?;
        let mut kept = BTreeMap::new();
        for raw in listed {
            let Some(account) = raw.account.and_then(|account| account.login) else {
                continue;
            };
            if raw.suspended_at.is_some() {
                continue;
            }
            let existing = self.installations.remove(&raw.id);
            match self
                .prepare(&app, raw.id, account, raw.repository_selection, existing)
                .await
            {
                Ok(installation) => {
                    kept.insert(raw.id, installation);
                }
                Err(error) => {
                    tracing::warn!(
                        installation = raw.id,
                        %error,
                        "an installation of the GitHub App could not be read; it is skipped until \
                         the next inventory"
                    );
                }
            }
        }
        self.installations = kept;
        Ok(())
    }

    async fn prepare(
        &self,
        app: &AuthenticatedClient,
        id: u64,
        account: String,
        selection: Option<String>,
        existing: Option<Installation>,
    ) -> Result<Installation, AppError> {
        let (client, demand, token_expires_at) = match existing {
            Some(mut installation) => {
                self.refresh_token_with(app, &mut installation).await?;
                (
                    installation.client,
                    installation.demand,
                    installation.token_expires_at,
                )
            }
            None => {
                let (token, expires_at) = mint_token(app, id).await?;
                let client = Arc::new(AuthenticatedClient::with_http_client(
                    self.http.clone(),
                    self.endpoints.clone(),
                    UserAccessToken::new(token),
                    Arc::clone(&self.clock),
                ));
                let demand = Arc::new(RestDemand::new(
                    Arc::clone(&client),
                    Arc::clone(&self.clock),
                ));
                (client, demand, expires_at)
            }
        };
        let repositories = list_repositories(&client).await?;
        Ok(Installation {
            id,
            account,
            all_repositories: selection.as_deref() == Some("all"),
            repositories,
            client,
            demand,
            token_expires_at,
        })
    }

    /// Replaces every installation token within [`TOKEN_REFRESH_WINDOW`] of
    /// expiry. An installation whose token cannot be renewed is dropped; the
    /// next inventory brings it back if it still exists.
    ///
    /// # Errors
    /// Signing the JWT.
    pub async fn refresh_tokens(&mut self) -> Result<(), AppError> {
        let now = self.clock.now();
        let due: Vec<u64> = self
            .installations
            .values()
            .filter(|installation| due(installation, now))
            .map(|installation| installation.id)
            .collect();
        if due.is_empty() {
            return Ok(());
        }
        let app = self.app_client()?;
        for id in due {
            let Some(mut installation) = self.installations.remove(&id) else {
                continue;
            };
            match self.refresh_token_with(&app, &mut installation).await {
                Ok(()) => {
                    self.installations.insert(id, installation);
                }
                Err(error) => {
                    tracing::warn!(
                        installation = id,
                        %error,
                        "an installation token could not be renewed; the installation is skipped \
                         until the next inventory"
                    );
                }
            }
        }
        Ok(())
    }

    async fn refresh_token_with(
        &self,
        app: &AuthenticatedClient,
        installation: &mut Installation,
    ) -> Result<(), AppError> {
        if !due(installation, self.clock.now()) {
            return Ok(());
        }
        let (token, expires_at) = mint_token(app, installation.id).await?;
        installation
            .client
            .replace_credential(UserAccessToken::new(token))
            .await;
        installation.token_expires_at = expires_at;
        tracing::info!(
            installation = installation.id,
            "an installation token was renewed"
        );
        Ok(())
    }

    /// Drops one installation, after its credential stopped working; the
    /// next inventory mints it afresh if it still exists.
    pub fn forget(&mut self, id: u64) {
        self.installations.remove(&id);
    }
}

fn due(installation: &Installation, now: Timestamp) -> bool {
    let window =
        chrono::TimeDelta::from_std(TOKEN_REFRESH_WINDOW).unwrap_or(chrono::TimeDelta::MAX);
    installation.token_expires_at - now <= window
}

/// Every page of a listing, up to [`MAX_PAGES`]; `items` takes one page's
/// items out of its envelope.
async fn paginate<P: DeserializeOwned, T>(
    client: &AuthenticatedClient,
    path: &str,
    items: impl Fn(P) -> Vec<T>,
) -> Result<Vec<T>, AppError> {
    let mut request = Some(ApiRequest::get(path).query("per_page", PER_PAGE));
    let mut all = Vec::new();
    for _ in 0..MAX_PAGES {
        let Some(next) = request.take() else {
            return Ok(all);
        };
        let response = client.send(&next).await?;
        request = response
            .next_page()
            .map(|url| ApiRequest::get(url.as_str()));
        all.extend(items(response.json::<P>()?));
    }
    if request.is_some() {
        tracing::warn!(
            pages = MAX_PAGES,
            "stopped a GitHub App listing at the page budget; what it did not reach is not swept"
        );
    }
    Ok(all)
}

async fn list_installations(app: &AuthenticatedClient) -> Result<Vec<RawInstallation>, AppError> {
    paginate(app, "/app/installations", |page: Vec<RawInstallation>| page).await
}

async fn mint_token(
    app: &AuthenticatedClient,
    id: u64,
) -> Result<(SecretString, Timestamp), AppError> {
    let response = app
        .send(&ApiRequest::new(
            Method::POST,
            format!("/app/installations/{id}/access_tokens"),
        ))
        .await?;
    let raw: RawToken = response.json()?;
    Ok((SecretString::from(raw.token), raw.expires_at))
}

async fn list_repositories(client: &AuthenticatedClient) -> Result<Vec<OwnerRepo>, AppError> {
    paginate(
        client,
        "/installation/repositories",
        |page: RawRepositories| {
            page.repositories
                .into_iter()
                .filter_map(|repository| OwnerRepo::parse(&repository.full_name).ok())
                .collect()
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer as _;
    use aws_lc_rs::rsa::KeySize;
    use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    #[test]
    fn a_jwt_is_rs256_over_the_app_id_and_verifies_with_the_public_key() {
        let generated = RsaKeyPair::generate(KeySize::Rsa2048).expect("key");
        let public = generated.public_key().as_ref().to_vec();
        let pkcs8 = generated.as_der().expect("der");
        let pem = SecretString::from(format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(pkcs8.as_ref())
        ));
        let key = AppKey::from_pem(42, &pem).expect("parses");
        assert_eq!(
            format!("{key:?}"),
            r#"AppKey { app_id: 42, key: "[redacted]" }"#
        );

        // GitHub hands out PKCS#1 (`RSA PRIVATE KEY`): the RSAPrivateKey a
        // 2048-bit PKCS#8 document wraps starts at byte 26.
        let pkcs1 = SecretString::from(format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
            STANDARD.encode(&pkcs8.as_ref()[26..])
        ));
        let same = AppKey::from_pem(42, &pkcs1).expect("PKCS#1 parses");

        let now = DateTime::from_timestamp(1_800_000_000, 0).expect("time");
        let jwt = key.jwt(now).expect("signs");
        let parts: Vec<&str> = jwt.expose_secret().split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("b64")).expect("json");
        assert_eq!(header["alg"], "RS256");
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("b64")).expect("json");
        assert_eq!(claims["iss"], "42");
        assert_eq!(claims["iat"], 1_800_000_000 - 60);
        assert_eq!(claims["exp"], 1_800_000_000 + 540);
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).expect("b64");
        let verifier = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public);
        verifier
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .expect("the signature verifies");
        let other = same.jwt(now).expect("signs");
        let other: Vec<&str> = other.expose_secret().split('.').collect();
        verifier
            .verify(
                format!("{}.{}", other[0], other[1]).as_bytes(),
                &URL_SAFE_NO_PAD.decode(other[2]).expect("b64"),
            )
            .expect("the PKCS#1 form is the same key");
    }

    #[test]
    fn a_key_that_is_not_one_is_refused_without_echoing_it() {
        let error = AppKey::from_pem(
            1,
            &SecretString::from(
                "-----BEGIN RSA PRIVATE KEY-----\nbm90IGEga2V5\n-----END RSA PRIVATE KEY-----",
            ),
        )
        .expect_err("refused");
        assert!(!error.to_string().contains("bm90"));
        assert!(AppKey::from_pem(1, &SecretString::from("not pem at all")).is_err());
    }
}
