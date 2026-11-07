//! The coordinator in-process, driven by a fake host over a real socket:
//! invite → enroll → connect → challenge → hello → signed webhook → wake.
//!
//! The fake host speaks either version: version 1 is a stage-1 host, which
//! must keep working against this coordinator unchanged.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::{SinkExt as _, StreamExt as _};
use hmac::{Hmac, KeyInit as _, Mac as _};
use runner_manager_coordinator::server::{AppState, Config, serve};
use runner_manager_coordinator::store::Store;
use runner_manager_coordinator_protocol::{
    CLOSE_UNAUTHORIZED, CLOSE_UNSUPPORTED_VERSION, EnrollRequest, EnrollResponse, Hello, HelloAck,
    HostMessage, HostSigningKey, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, Profile, ServerMessage,
    Target, TargetScope, Wake, WakeReason, decode_nonce, encode_public_key, sign_challenge,
    signing_key_from_seed,
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::Sha256;
use tokio_tungstenite::tungstenite::Message;

const SECRET: &str = "a-webhook-secret-for-tests";

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct Coordinator {
    base: String,
    state: Arc<AppState>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn start() -> Coordinator {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let mut config = Config::new(base.clone(), SecretString::from(SECRET));
    config.revocation_check = Duration::from_millis(100);
    let state = AppState::new(config, Store::open_in_memory().expect("store"));
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    tokio::spawn(serve(listener, Arc::clone(&state), async {
        let _ = stopped.await;
    }));
    Coordinator {
        base,
        state,
        _shutdown: shutdown,
    }
}

impl Coordinator {
    fn invite(&self, name: &str) -> String {
        self.state
            .store
            .lock()
            .expect("store")
            .create_invite(name, Duration::from_secs(900), Utc::now())
            .expect("invite")
            .code
            .expose_secret()
            .to_string()
    }

    async fn enroll(&self, code: &str, key: &HostSigningKey) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/enroll", self.base))
            .json(&EnrollRequest {
                // Enrollment is unchanged since version 1, and sent as 1.
                protocol_version: MIN_PROTOCOL_VERSION,
                code: code.to_string(),
                hostname: "test-box".into(),
                public_key: encode_public_key(&key.verifying_key()),
            })
            .send()
            .await
            .expect("sent")
    }

    async fn webhook(&self, event: &str, delivery: &str, body: &str, sign: bool) -> u16 {
        let mut request = reqwest::Client::new()
            .post(format!("{}/webhook", self.base))
            .header("x-github-event", event)
            .header("x-github-delivery", delivery)
            .body(body.to_string());
        if sign {
            let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).expect("key");
            mac.update(body.as_bytes());
            request = request.header(
                "x-hub-signature-256",
                format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
            );
        }
        request.send().await.expect("sent").status().as_u16()
    }

    async fn connect(&self, host_id: &str, key: &HostSigningKey) -> Socket {
        self.connect_at(PROTOCOL_VERSION, host_id, key).await
    }

    /// Connects as a host speaking `version`; a version-1 host checks the
    /// challenge the way stage 1 did.
    async fn connect_at(&self, version: u32, host_id: &str, key: &HostSigningKey) -> Socket {
        let url = self.base.replacen("http://", "ws://", 1) + "/connect";
        let (mut socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("connected");
        let ServerMessage::Challenge {
            protocol_version,
            nonce,
            max_protocol_version,
        } = next(&mut socket).await
        else {
            panic!("the first message is a challenge");
        };
        assert_eq!(protocol_version, 1, "what a stage-1 host requires");
        assert_eq!(max_protocol_version, Some(PROTOCOL_VERSION));
        let nonce = decode_nonce(&nonce).expect("nonce");
        let auth = HostMessage::Auth {
            protocol_version: version,
            host_id: host_id.to_string(),
            signature: sign_challenge(key, &nonce, &self.base),
        };
        socket
            .send(Message::Text(auth.encode().into()))
            .await
            .expect("sent");
        socket
    }
}

async fn next(socket: &mut Socket) -> ServerMessage {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("a message in time")
            .expect("open")
            .expect("readable");
        if let Message::Text(text) = frame {
            return ServerMessage::decode(&text).expect("decodes");
        }
    }
}

/// The close code the server ended the connection with.
async fn closed_with(socket: &mut Socket) -> Option<u16> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("closed in time")
        {
            Some(Ok(Message::Close(frame))) => return frame.map(|f| u16::from(f.code)),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return None,
        }
    }
}

fn hello(version: u32, host_id: &str) -> HostMessage {
    HostMessage::Hello(Hello {
        protocol_version: version,
        host_id: host_id.to_string(),
        os: "linux".into(),
        arch: "x64".into(),
        cores: 8,
        ram_bytes: Some(1 << 34),
        disk_free_bytes: None,
        targets: vec![Target {
            scope: TargetScope::Org,
            name: "octo".into(),
            profiles: vec![Profile {
                name: "default".into(),
                labels: vec!["self-hosted".into(), "linux".into()],
                enabled: true,
            }],
        }],
    })
}

fn queued(repository: &str, labels: &[&str]) -> String {
    serde_json::json!({
        "action": "queued",
        "workflow_job": {"id": 1, "run_id": 2, "labels": labels},
        "repository": {"full_name": repository},
    })
    .to_string()
}

async fn enrolled(coordinator: &Coordinator, name: &str, seed: u8) -> (String, HostSigningKey) {
    let key = signing_key_from_seed(&[seed; 32]);
    let response = coordinator.enroll(&coordinator.invite(name), &key).await;
    assert_eq!(response.status(), 200);
    let enrolled: EnrollResponse = response.json().await.expect("json");
    assert_eq!(enrolled.name, name);
    (enrolled.host_id, key)
}

async fn wait_for_hello(coordinator: &Coordinator) {
    for _ in 0..100 {
        if coordinator
            .state
            .registry
            .connected()
            .iter()
            .any(|host| host.hello.is_some())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the hello never arrived");
}

#[tokio::test]
async fn a_version_two_host_is_told_its_coverage_and_woken() {
    let coordinator = start().await;
    let (host_id, key) = enrolled(&coordinator, "linux-new", 7).await;
    let mut socket = coordinator.connect(&host_id, &key).await;
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Welcome {
            protocol_version: PROTOCOL_VERSION,
            ..
        }
    ));
    socket
        .send(Message::Text(
            hello(PROTOCOL_VERSION, &host_id).encode().into(),
        ))
        .await
        .expect("hello");
    // No GitHub App here: no sweep, so nothing is covered.
    assert_eq!(
        next(&mut socket).await,
        ServerMessage::HelloAck(HelloAck::default())
    );
    let body = queued("octo/app", &["self-hosted", "linux"]);
    assert_eq!(
        coordinator
            .webhook("workflow_job", "n-1", &body, true)
            .await,
        200
    );
    assert!(matches!(next(&mut socket).await, ServerMessage::Wake(_)));

    // A hello at a version other than the negotiated one is refused.
    socket
        .send(Message::Text(hello(1, &host_id).encode().into()))
        .await
        .expect("hello");
    assert_eq!(
        closed_with(&mut socket).await,
        Some(CLOSE_UNSUPPORTED_VERSION)
    );
    let mut socket = coordinator.connect_at(3, &host_id, &key).await;
    assert_eq!(
        closed_with(&mut socket).await,
        Some(CLOSE_UNSUPPORTED_VERSION)
    );
}

/// A stage-1 host against this coordinator: version 1 throughout, no
/// `hello_ack`, and wakes exactly as before.
#[tokio::test]
async fn a_queued_job_wakes_the_enrolled_host_that_serves_it() {
    let coordinator = start().await;
    assert_eq!(
        reqwest::get(format!("{}/healthz", coordinator.base))
            .await
            .expect("health")
            .status(),
        200
    );
    let (host_id, key) = enrolled(&coordinator, "linux-big", 1).await;
    let mut socket = coordinator.connect_at(1, &host_id, &key).await;
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Welcome {
            protocol_version: 1,
            ..
        }
    ));
    socket
        .send(Message::Text(hello(1, &host_id).encode().into()))
        .await
        .expect("hello");
    wait_for_hello(&coordinator).await;

    // Unsigned: a bare 401, and nothing is woken.
    let body = queued("octo/app", &["self-hosted", "Linux"]);
    assert_eq!(
        coordinator
            .webhook("workflow_job", "d-0", &body, false)
            .await,
        401
    );
    assert_eq!(coordinator.webhook("ping", "d-ping", "{}", true).await, 200);
    // A job no profile here can take wakes nobody.
    let windows = queued("octo/app", &["windows"]);
    assert_eq!(
        coordinator
            .webhook("workflow_job", "d-win", &windows, true)
            .await,
        200
    );
    assert_eq!(
        coordinator
            .webhook("workflow_job", "d-1", &body, true)
            .await,
        200
    );
    let ServerMessage::Wake(wake) = next(&mut socket).await else {
        panic!("a wake");
    };
    assert_eq!(
        wake,
        Wake {
            target: runner_manager_coordinator_protocol::TargetRef {
                scope: TargetScope::Org,
                name: "octo".into()
            },
            repository: "octo/app".into(),
            reason: WakeReason::JobQueued,
            delivery_id: "d-1".into(),
        }
    );
    // The same delivery again is acknowledged and not acted on.
    assert_eq!(
        coordinator
            .webhook("workflow_job", "d-1", &body, true)
            .await,
        200
    );
    assert_eq!(
        coordinator
            .webhook("workflow_job", "d-2", &body, true)
            .await,
        200
    );
    let ServerMessage::Wake(second) = next(&mut socket).await else {
        panic!("a wake");
    };
    assert_eq!(second.delivery_id, "d-2", "d-1's repeat produced no wake");
}

#[tokio::test]
async fn an_enrollment_code_works_once() {
    let coordinator = start().await;
    let code = coordinator.invite("mac");
    let key = signing_key_from_seed(&[2; 32]);
    assert_eq!(coordinator.enroll(&code, &key).await.status(), 200);
    assert_eq!(coordinator.enroll(&code, &key).await.status(), 401);
    assert_eq!(coordinator.enroll("rmc_nope", &key).await.status(), 401);
}

#[tokio::test]
async fn a_wrong_key_an_unknown_host_and_a_revoked_host_are_refused() {
    let coordinator = start().await;
    let (host_id, key) = enrolled(&coordinator, "win", 3).await;

    let impostor = signing_key_from_seed(&[4; 32]);
    let mut socket = coordinator.connect(&host_id, &impostor).await;
    assert_eq!(closed_with(&mut socket).await, Some(CLOSE_UNAUTHORIZED));

    let mut socket = coordinator.connect("no-such-host", &key).await;
    assert_eq!(closed_with(&mut socket).await, Some(CLOSE_UNAUTHORIZED));

    // Connected, then revoked from the admin side: the link is cut.
    let mut socket = coordinator.connect(&host_id, &key).await;
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Welcome { .. }
    ));
    coordinator
        .state
        .store
        .lock()
        .expect("store")
        .revoke("win", Utc::now())
        .expect("revoked");
    assert_eq!(closed_with(&mut socket).await, Some(CLOSE_UNAUTHORIZED));
    let mut socket = coordinator.connect(&host_id, &key).await;
    assert_eq!(closed_with(&mut socket).await, Some(CLOSE_UNAUTHORIZED));
}
