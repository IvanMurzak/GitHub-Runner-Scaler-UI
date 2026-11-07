//! The coordinator's GitHub App credentials never reach a log line: drive a
//! whole sweep (JWT, installation token, renewal, listings, wake) through a
//! capturing subscriber at TRACE and scan it for the private key, every JWT
//! and every installation token.
//!
//! One test in its own binary, for the reason
//! `crates/github/tests/no_secret_reaches_the_logs.rs` records: `tracing`'s
//! callsite interest is process-wide, and other tests running concurrently
//! would blind the capture.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    INSTALLATION, TOKEN_ONE, TOKEN_TWO, app, app_keys, bearer_tokens, fake_github, host, queue,
};
use runner_manager_coordinator::registry::Registry;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("capture").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn no_secret_reaches_the_logs() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let keys = app_keys();
    let jwts = tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            // Five-minute tokens, so the renewal path is in the scan too.
            let server = fake_github(&keys, Duration::from_secs(5 * 60)).await;
            queue(&server).await;
            let registry = Arc::new(Registry::default());
            let _rx = host(&registry);
            let app = app(&keys, &server);
            tracing::info!(?app, "the App, rendered through Debug");
            let mut sweeper = common::sweeper(app, &registry);
            let first = sweeper.sweep_once().await;
            assert_eq!(first.wakes, 1, "the sweep ran end to end");
            sweeper.sweep_once().await;
            bearer_tokens(
                &server,
                &format!("/app/installations/{INSTALLATION}/access_tokens"),
            )
            .await
        })
    });

    let logs = String::from_utf8(capture.0.lock().expect("capture").clone()).expect("utf-8");
    // The capture is not blind: library and coordinator callsites are in it.
    for expected in [
        "github api request",
        "an installation token was renewed",
        "the App, rendered through Debug",
    ] {
        assert!(logs.contains(expected), "missing `{expected}`:\n{logs}");
    }
    assert!(jwts.len() >= 2, "JWTs were minted and used");
    for jwt in &jwts {
        let signature = jwt.rsplit('.').next().expect("signature");
        assert!(!logs.contains(signature), "a JWT reached the logs:\n{logs}");
    }
    for token in [TOKEN_ONE, TOKEN_TWO] {
        assert!(
            !logs.contains(token),
            "an installation token reached the logs:\n{logs}"
        );
    }
    // Any 40 characters of the key body would be a leak.
    for chunk in keys.pem_body.as_bytes().chunks(40).take(10) {
        let chunk = std::str::from_utf8(chunk).expect("ascii");
        assert!(!logs.contains(chunk), "the private key reached the logs");
    }
    assert!(!logs.to_ascii_lowercase().contains("bearer "));
}
