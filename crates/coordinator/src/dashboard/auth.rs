//! Sign-in to the dashboard with GitHub (the OAuth web flow), for an
//! allowlist of GitHub logins only.
//!
//! GitHub's access token is used once, to ask who signed in, and dropped: it
//! is never stored or logged. The session cookie is 32 random bytes; the
//! database keeps only its SHA-256, so a copy of the database (a backup)
//! signs nobody in. A login taken off the allowlist loses its sessions when
//! the server starts.

use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

/// How long a session lasts.
pub const SESSION_SECS: i64 = 30 * 24 * 60 * 60;
/// How long a sign-in may take between leaving for GitHub and coming back.
pub const STATE_SECS: i64 = 10 * 60;

/// The dashboard's sign-in settings.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// The OAuth app's (or GitHub App's) client id.
    pub client_id: String,
    pub client_secret: SecretString,
    /// GitHub logins allowed in, compared without case.
    pub allowed_logins: Vec<String>,
    /// `https://github.com`, or a test server.
    pub web_base: String,
    /// `https://api.github.com`, or a test server.
    pub api_base: String,
}

impl AuthConfig {
    #[must_use]
    pub fn allows(&self, login: &str) -> bool {
        self.allowed_logins
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(login))
    }
}

/// Who signed in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GithubUser {
    pub login: String,
    #[serde(default)]
    pub avatar_url: Option<String>,
}

/// Why a sign-in failed. Fixed words only: nothing GitHub sent is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignInError {
    #[error("GitHub could not be reached")]
    Unreachable,
    #[error("GitHub refused the sign-in code")]
    Refused,
    #[error("GitHub's answer was not understood")]
    Malformed,
}

/// A fresh random token, hex-encoded: a session cookie or an OAuth `state`.
#[must_use]
pub fn token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

/// What the database keeps of a session cookie.
#[must_use]
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Whether two tokens are equal, in time that does not depend on where they
/// differ.
#[must_use]
pub fn same_token(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0_u8, |difference, (x, y)| difference | (x ^ y))
            == 0
}

/// Where GitHub's sign-in page is, for `state` and `redirect_uri`.
#[must_use]
pub fn authorize_url(config: &AuthConfig, redirect_uri: &str, state: &str) -> String {
    let mut url = url::Url::parse(&format!("{}/login/oauth/authorize", config.web_base))
        .unwrap_or_else(|_| {
            url::Url::parse("https://github.com/login/oauth/authorize").expect("a URL")
        });
    url.query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state)
        .append_pair("allow_signup", "false");
    url.into()
}

/// Trades GitHub's one-time `code` for the user who signed in.
///
/// # Errors
/// GitHub unreachable, refusing the code, or answering in an unknown shape.
pub async fn who_signed_in(
    http: &reqwest::Client,
    config: &AuthConfig,
    code: &str,
    redirect_uri: &str,
) -> Result<GithubUser, SignInError> {
    #[derive(Deserialize)]
    struct Token {
        access_token: Option<String>,
    }
    let token: Token = http
        .post(format!("{}/login/oauth/access_token", config.web_base))
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&serde_json::json!({
            "client_id": config.client_id,
            "client_secret": config.client_secret.expose_secret(),
            "code": code,
            "redirect_uri": redirect_uri,
        }))
        .send()
        .await
        .map_err(|_| SignInError::Unreachable)?
        .error_for_status()
        .map_err(|_| SignInError::Refused)?
        .json()
        .await
        .map_err(|_| SignInError::Malformed)?;
    let access = SecretString::from(token.access_token.ok_or(SignInError::Refused)?);
    http.get(format!("{}/user", config.api_base))
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header(reqwest::header::USER_AGENT, "runner-manager-coordinator")
        .bearer_auth(access.expose_secret())
        .send()
        .await
        .map_err(|_| SignInError::Unreachable)?
        .error_for_status()
        .map_err(|_| SignInError::Refused)?
        .json::<GithubUser>()
        .await
        .map_err(|_| SignInError::Malformed)
}

/// The value of cookie `name` in a request's `Cookie` headers.
#[must_use]
pub fn cookie<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

/// A `Set-Cookie` value. `secure` is false only for a plain-HTTP origin
/// (local testing), where a browser would drop a `Secure` cookie.
#[must_use]
pub fn set_cookie(name: &str, value: &str, max_age: i64, secure: bool) -> String {
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_and_compared_whole() {
        let a = token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, token());
        assert!(same_token(&a, &a.clone()));
        assert!(!same_token(&a, &token()));
        assert!(!same_token(&a, &a[..63]));
        assert_ne!(token_hash(&a), a);
    }

    #[test]
    fn the_allowlist_ignores_case_and_nothing_else() {
        let config = AuthConfig {
            client_id: "id".into(),
            client_secret: SecretString::from("s"),
            allowed_logins: vec!["IvanMurzak".into()],
            web_base: "https://github.com".into(),
            api_base: "https://api.github.com".into(),
        };
        assert!(config.allows("ivanmurzak"));
        assert!(!config.allows("ivanmurzak2"));
        assert!(!config.allows(""));
        let url = authorize_url(&config, "https://r.example/auth/callback", "abc");
        assert!(url.starts_with("https://github.com/login/oauth/authorize?client_id=id&"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fr.example%2Fauth%2Fcallback"));
    }

    #[test]
    fn a_cookie_is_found_among_others() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "a=1; rm_session=xyz; b=2".parse().unwrap(),
        );
        assert_eq!(cookie(&headers, "rm_session"), Some("xyz"));
        assert_eq!(cookie(&headers, "rm"), None);
        assert!(set_cookie("n", "v", 5, true).ends_with("Max-Age=5; Secure"));
    }
}
