use std::cell::RefCell;

use super::*;
use serde_json::json;

#[derive(Default)]
struct FakeEngine {
    resources: RefCell<BTreeMap<String, Value>>,
    calls: RefCell<Vec<(String, String)>>,
    in_use: RefCell<BTreeSet<String>>,
    replaced: bool,
}

impl Engine for FakeEngine {
    fn request(&self, method: &str, path: &str, _body: Option<&Value>) -> io::Result<Reply> {
        self.calls.borrow_mut().push((method.into(), path.into()));
        assert!(
            !path.contains("prune"),
            "a host-wide prune must never be called"
        );
        if path == "/info" {
            return Ok(Reply {
                status: 200,
                body: json!({"ID":if self.replaced { "another-engine" } else { "fixture-engine" }}),
            });
        }
        let key = path.split('?').next().unwrap().trim_end_matches("/json");
        if method == "GET" {
            return Ok(match self.resources.borrow().get(key) {
                Some(value) => Reply {
                    status: 200,
                    body: value.clone(),
                },
                None => Reply {
                    status: 404,
                    body: Value::Null,
                },
            });
        }
        assert_eq!(method, "DELETE");
        if key.starts_with("/volumes/") || key.starts_with("/networks/") {
            assert!(!path.contains("force"));
        }
        if self.in_use.borrow().contains(key) {
            return Ok(Reply {
                status: 409,
                body: Value::Null,
            });
        }
        let found = self.resources.borrow_mut().remove(key).is_some();
        Ok(Reply {
            status: if found { 204 } else { 404 },
            body: Value::Null,
        })
    }
}

fn journal() -> Journal {
    Journal::new(
        HostId::from_u128(1),
        AttemptId::from_u128(2),
        "owner/repo".into(),
        PathBuf::from(if cfg!(windows) {
            "C:\\fixture.sock"
        } else {
            "/fixture.sock"
        }),
        "fixture-engine".into(),
    )
}

fn id(value: u64) -> String {
    format!("{value:064x}")
}

fn intent(journal: &mut Journal, kind: Kind, body: &mut Value) -> Intent {
    let endpoint = format!("/v1.49/{}/create", kind.collection());
    let intent = creation_intent(journal, &endpoint, body).unwrap().unwrap();
    journal.intents.push(intent.clone());
    intent
}

fn insert(
    engine: &FakeEngine,
    journal: &Journal,
    intent: &Intent,
    kind: Kind,
    id: &str,
    implicit: bool,
) {
    let labels = if implicit {
        json!({"com.docker.volume.anonymous":""})
    } else {
        serde_json::to_value(journal.labels(&intent.id)).unwrap()
    };
    let value = match kind {
        Kind::Container => {
            json!({"Id":id,"Created":"2026-10-30T00:00:00Z","Config":{"Labels":labels},"Mounts":[]})
        }
        Kind::Volume => json!({"Name":id,"CreatedAt":"2026-10-30T00:00:00Z","Labels":labels}),
        Kind::Network => json!({"Id":id,"Created":"2026-10-30T00:00:00Z","Labels":labels}),
    };
    engine
        .resources
        .borrow_mut()
        .insert(format!("/{}/{id}", kind.collection()), value);
}

#[test]
fn named_volumes_builders_retained_resources_and_build_requests_are_not_owned() {
    let journal = journal();
    for (path, mut body) in [
        ("/v1.49/volumes/create", json!({"Name":"cache"})),
        ("/v1.49/volumes/create", json!({"Name":id(7)})),
        (
            "/v1.49/containers/create",
            json!({"Labels":{RETAIN_LABEL:"true"}}),
        ),
        (
            "/v1.49/containers/create?name=buildx_buildkit_shared0",
            json!({"Image":"custom/builder"}),
        ),
        (
            "/v1.49/containers/create",
            json!({"Image":"custom/builder","HostConfig":{"Mounts":[{"Source":"builder-state","Target":"/var/lib/buildkit","Type":"volume"}]}}),
        ),
        ("/v1.49/build", json!({"arbitrary":"build cache"})),
    ] {
        let before = body.clone();
        assert!(
            creation_intent(&journal, path, &mut body)
                .unwrap()
                .is_none(),
            "{path}"
        );
        assert_eq!(body, before);
    }
}

#[test]
fn ownership_labels_cannot_be_overwritten_and_secrets_never_enter_the_journal() {
    let mut journal = journal();
    let mut foreign = json!({"Labels":{HOST_LABEL:"another-host"}});
    assert!(creation_intent(&journal, "/containers/create", &mut foreign).is_err());
    let mut body = json!({"Image":"fixture","Env":["TOKEN=secret-not-for-the-journal"],"Labels":{"user-label":"kept"},"HostConfig":{"Binds":["shared:/secret-not-for-the-journal"]}});
    let operation = intent(&mut journal, Kind::Container, &mut body);
    assert_eq!(body["Labels"]["user-label"], "kept");
    assert_eq!(body["Labels"][OPERATION_LABEL], operation.id);
    assert!(
        !serde_json::to_string(&journal)
            .unwrap()
            .contains("secret-not-for-the-journal")
    );
}

#[test]
fn implicit_mount_is_recorded_but_explicit_named_or_reused_anonymous_mounts_are_not() {
    let mut journal = journal();
    let mut body = json!({"HostConfig":{"Binds":[format!("{}:/reused",id(12)),"cache:/cache"],"Mounts":[{"Type":"volume","Source":id(13),"Target":"/mounted"}]}});
    let operation = intent(&mut journal, Kind::Container, &mut body);
    let engine = FakeEngine::default();
    insert(
        &engine,
        &journal,
        &operation,
        Kind::Container,
        &id(10),
        false,
    );
    let mut mounts = Vec::new();
    for (number, destination) in [
        (11, "/new"),
        (12, "/reused"),
        (13, "/mounted"),
        (14, "/cache"),
    ] {
        insert(
            &engine,
            &journal,
            &operation,
            Kind::Volume,
            &id(number),
            true,
        );
        mounts.push(json!({"Type":"volume","Name":id(number),"Destination":destination}));
    }
    engine
        .resources
        .borrow_mut()
        .get_mut(&format!("/containers/{}", id(10)))
        .unwrap()["Mounts"] = json!(mounts);
    capture_created(&mut journal, &operation, &id(10), &engine).unwrap();
    assert_eq!(journal.resources.len(), 2);
    assert!(
        journal
            .resources
            .iter()
            .any(|resource| resource.kind == Kind::Volume
                && resource.id == id(11)
                && resource.implicit_volume)
    );
}

#[test]
fn inherited_volumes_are_never_claimed() {
    let mut journal = journal();
    let mut body = json!({"HostConfig":{"VolumesFrom":["another-container"]}});
    let operation = intent(&mut journal, Kind::Container, &mut body);
    let engine = FakeEngine::default();
    insert(
        &engine,
        &journal,
        &operation,
        Kind::Container,
        &id(10),
        false,
    );
    insert(&engine, &journal, &operation, Kind::Volume, &id(11), true);
    engine
        .resources
        .borrow_mut()
        .get_mut(&format!("/containers/{}", id(10)))
        .unwrap()["Mounts"] = json!([{"Type":"volume","Name":id(11),"Destination":"/data"}]);
    capture_created(&mut journal, &operation, &id(10), &engine).unwrap();
    assert_eq!(journal.resources.len(), 1);
    assert_eq!(journal.resources[0].kind, Kind::Container);
}

#[test]
fn report_is_read_only_and_apply_deletes_owned_resources_in_dependency_order() {
    let mut journal = journal();
    let engine = FakeEngine::default();
    for (kind, number) in [(Kind::Network, 1), (Kind::Volume, 2), (Kind::Container, 3)] {
        let operation = intent(&mut journal, kind, &mut json!({}));
        insert(&engine, &journal, &operation, kind, &id(number), false);
        capture_created(&mut journal, &operation, &id(number), &engine).unwrap();
    }
    let report = clean_resources(&mut journal, &engine, Mode::Report).unwrap();
    assert_eq!(report.candidates, 3);
    assert_eq!(report.details.len(), 3);
    assert!(
        report
            .details
            .iter()
            .all(|detail| detail.attempt == journal.attempt && detail.outcome == "would_remove")
    );
    assert_eq!(engine.resources.borrow().len(), 3);
    assert!(
        !engine
            .calls
            .borrow()
            .iter()
            .any(|(method, _)| method == "DELETE")
    );
    let applied = clean_resources(&mut journal, &engine, Mode::Apply).unwrap();
    assert_eq!(applied.removed, 3);
    let calls = engine.calls.borrow();
    let deletes: Vec<_> = calls
        .iter()
        .filter(|(method, _)| method == "DELETE")
        .map(|(_, path)| path.as_str())
        .collect();
    assert!(deletes[0].starts_with("/containers/"));
    assert!(deletes[1].starts_with("/volumes/"));
    assert!(deletes[2].starts_with("/networks/"));
    assert!(journal.resources.is_empty());
}

#[test]
fn engine_swap_prevents_every_mutation() {
    let mut journal = journal();
    let operation = intent(&mut journal, Kind::Container, &mut json!({}));
    let mut engine = FakeEngine::default();
    insert(
        &engine,
        &journal,
        &operation,
        Kind::Container,
        &id(1),
        false,
    );
    capture_created(&mut journal, &operation, &id(1), &engine).unwrap();
    engine.replaced = true;
    assert!(clean_resources(&mut journal, &engine, Mode::Apply).is_err());
    assert!(
        !engine
            .calls
            .borrow()
            .iter()
            .any(|(method, _)| method == "DELETE")
    );
}

#[test]
fn retained_foreign_and_recreated_resources_are_protected() {
    for change in ["retain", "owner", "created"] {
        let mut journal = journal();
        let operation = intent(&mut journal, Kind::Container, &mut json!({}));
        let engine = FakeEngine::default();
        insert(
            &engine,
            &journal,
            &operation,
            Kind::Container,
            &id(1),
            false,
        );
        capture_created(&mut journal, &operation, &id(1), &engine).unwrap();
        {
            let mut resources = engine.resources.borrow_mut();
            let value = resources
                .get_mut(&format!("/containers/{}", id(1)))
                .unwrap();
            match change {
                "retain" => value["Config"]["Labels"][RETAIN_LABEL] = json!("true"),
                "owner" => value["Config"]["Labels"][HOST_LABEL] = json!("foreign"),
                _ => value["Created"] = json!("recreated"),
            }
        }
        assert_eq!(
            clean_resources(&mut journal, &engine, Mode::Apply)
                .unwrap()
                .protected,
            1
        );
        assert_eq!(engine.resources.borrow().len(), 1);
    }
}

#[test]
fn a_volume_used_by_another_container_is_retained_and_retried() {
    let mut journal = journal();
    let operation = intent(&mut journal, Kind::Volume, &mut json!({}));
    let engine = FakeEngine::default();
    insert(&engine, &journal, &operation, Kind::Volume, &id(1), false);
    capture_created(&mut journal, &operation, &id(1), &engine).unwrap();
    engine
        .in_use
        .borrow_mut()
        .insert(format!("/volumes/{}", id(1)));
    assert_eq!(
        clean_resources(&mut journal, &engine, Mode::Apply)
            .unwrap()
            .pending,
        1
    );
    assert_eq!(journal.resources.len(), 1);
    engine.in_use.borrow_mut().clear();
    assert_eq!(
        clean_resources(&mut journal, &engine, Mode::Apply)
            .unwrap()
            .removed,
        1
    );
    assert!(journal.resources.is_empty());
}

#[test]
fn missing_resources_and_off_mode_are_idempotent() {
    let mut journal = journal();
    let operation = intent(&mut journal, Kind::Container, &mut json!({}));
    let engine = FakeEngine::default();
    insert(
        &engine,
        &journal,
        &operation,
        Kind::Container,
        &id(1),
        false,
    );
    capture_created(&mut journal, &operation, &id(1), &engine).unwrap();
    clean_resources(&mut journal, &engine, Mode::Off).unwrap();
    assert_eq!(journal.resources.len(), 1);
    engine.resources.borrow_mut().clear();
    clean_resources(&mut journal, &engine, Mode::Apply).unwrap();
    assert!(journal.resources.is_empty());
    clean_resources(&mut journal, &engine, Mode::Apply).unwrap();
}

#[test]
fn durable_journal_replacement_and_schema_checks_survive_a_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("journal.json");
    let mut journal = journal();
    write_json(&path, &journal).unwrap();
    let operation = intent(&mut journal, Kind::Network, &mut json!({}));
    journal.proxy = Some(ProcessIdentity::of_current_process().unwrap());
    write_json(&path, &journal).unwrap();
    let loaded = Journal::load(&path).unwrap();
    assert_eq!(loaded.intents[0].id, operation.id);
    journal.schema += 1;
    write_json(&path, &journal).unwrap();
    assert!(Journal::load(&path).is_err());
    assert_eq!(
        Config::load(&root.path().join("absent")).unwrap().mode,
        Mode::Report
    );
}

#[test]
fn journal_rejects_duplicate_operations_and_unowned_resource_associations() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("journal.json");
    let mut journal = journal();
    let operation = intent(&mut journal, Kind::Network, &mut json!({}));
    journal.proxy = Some(ProcessIdentity::of_current_process().unwrap());
    journal.intents.push(operation.clone());
    write_json(&path, &journal).unwrap();
    assert!(Journal::load(&path).is_err());
    journal.intents.pop();
    journal.resources.push(Resource {
        kind: Kind::Volume,
        id: id(1),
        created: "fixture-time".into(),
        operation: operation.id,
        implicit_volume: true,
    });
    write_json(&path, &journal).unwrap();
    assert!(Journal::load(&path).is_err());
    journal.resources.clear();
    write_json(&path, &journal).unwrap();
    assert!(Journal::load(&path).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn explicit_context_and_remote_endpoints_never_start_a_proxy_or_change_routing() {
    use std::os::unix::net::UnixListener;
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("mock.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    let cleanup = DockerCleanup::new(
        HostId::from_u128(1),
        &root.path().join("config"),
        &root.path().join("state"),
    );
    let mut env = runner_manager_platform::runner_env::RunnerEnv::default();
    env.set("DOCKER_HOST", &format!("unix://{}", socket.display()))
        .unwrap();
    env.set("DOCKER_CONTEXT", "operator-selected").unwrap();
    assert!(
        cleanup
            .launch_environment(AttemptId::from_u128(2), "owner/repo", &env)
            .unwrap()
            .is_none()
    );
    assert!(!cleanup.root.exists());
    env.unset("DOCKER_CONTEXT");
    env.set("DOCKER_HOST", "tcp://operator-engine:2376")
        .unwrap();
    assert!(
        cleanup
            .launch_environment(AttemptId::from_u128(2), "owner/repo", &env)
            .unwrap()
            .is_none()
    );
    assert!(!cleanup.root.exists());
}
