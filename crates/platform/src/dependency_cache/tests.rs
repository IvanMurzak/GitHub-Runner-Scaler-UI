use std::cell::Cell;
use std::collections::BTreeSet;

use super::*;

const WINDOWS: RunnerPlatform = RunnerPlatform::Windows;
const MACOS: RunnerPlatform = RunnerPlatform::MacOs;
const LINUX: RunnerPlatform = RunnerPlatform::Linux;
const PLATFORMS: [RunnerPlatform; 3] = [WINDOWS, MACOS, LINUX];

fn repo(slug: &str) -> ScaleTarget {
    ScaleTarget::repository(slug).unwrap()
}

fn org(name: &str) -> ScaleTarget {
    ScaleTarget::organization(name).unwrap()
}

fn names_on(platform: RunnerPlatform, config: &CacheConfig) -> Vec<&'static str> {
    let selection = select(config, &repo("o/r"), platform);
    let (variables, _) = environment(
        selection.enabled_tools(),
        Path::new("/ns"),
        Path::new("/ns/_slots/1"),
        platform,
    );
    variables.into_iter().map(|(name, _)| name).collect()
}

// -- the table ---------------------------------------------------------------

#[test]
fn every_tool_id_directory_and_variable_name_is_unique_on_every_platform() {
    let ids: BTreeSet<_> = TOOLS.iter().map(|tool| tool.id).collect();
    assert_eq!(ids.len(), TOOLS.len(), "a tool id is listed twice");
    for platform in PLATFORMS {
        let mut dirs = BTreeSet::new();
        let mut names = BTreeSet::new();
        for tool in TOOLS.iter().filter(|tool| tool.applies_to(platform)) {
            assert!(
                dirs.insert((tool.sharing == Sharing::Slot, tool.dir)),
                "{} shares a directory on {platform:?}",
                tool.id
            );
            assert!(
                tool.dir != SLOTS_DIR && !tool.dir.starts_with('.'),
                "{} would collide with the namespace's own entries",
                tool.id
            );
            for variable in tool.variables_on(platform) {
                // Windows compares names without case; one name set twice
                // would be decided by the order of `Command::env` calls.
                let key = if platform == WINDOWS {
                    variable.name.to_ascii_uppercase()
                } else {
                    variable.name.to_owned()
                };
                assert!(
                    names.insert(key),
                    "{} is set twice on {platform:?}",
                    variable.name
                );
                assert!(
                    !crate::runner_env::RESERVED_NAMES
                        .iter()
                        .any(|reserved| reserved.eq_ignore_ascii_case(variable.name)),
                    "{} is reserved for the per-attempt temporary directory",
                    variable.name
                );
            }
        }
    }
}

/// The variables a repository gets by default on each platform, spelled out
/// so a change to the table is a deliberate change to this list. Run on every
/// CI leg: the platform is a parameter, not a `cfg`.
#[test]
fn the_default_variables_are_these_on_each_platform() {
    let common = [
        "RUNNER_TOOL_CACHE",
        "AGENT_TOOLSDIRECTORY",
        "DOTNET_INSTALL_DIR",
        "npm_config_cache",
        "npm_config_store_dir",
        "PNPM_CONFIG_STORE_DIR",
        "YARN_GLOBAL_FOLDER",
        "BUN_INSTALL_CACHE_DIR",
        "DENO_DIR",
        "npm_config_devdir",
        "npm_package_config_node_gyp_devdir",
        "electron_config_cache",
    ];
    let after_electron = [
        "ELECTRON_BUILDER_CACHE",
        "PLAYWRIGHT_BROWSERS_PATH",
        "PLAYWRIGHT_SKIP_BROWSER_GC",
        "CYPRESS_CACHE_FOLDER",
        "NUGET_PACKAGES",
        "NUGET_HTTP_CACHE_PATH",
        "NUGET_PLUGINS_CACHE_PATH",
        "NUGET_SCRATCH",
        "PIP_CACHE_DIR",
        "UV_CACHE_DIR",
        "GOMODCACHE",
        "GOCACHE",
        "COMPOSER_CACHE_DIR",
    ];
    let config = CacheConfig::default();

    let mut windows: Vec<&str> = common.to_vec();
    windows.extend(after_electron);
    windows.push("CCACHE_DIR");
    assert_eq!(names_on(WINDOWS, &config), windows);

    let mut unix = vec!["XDG_CACHE_HOME"];
    unix.extend(common);
    unix.push("ELECTRON_CACHE");
    unix.extend(after_electron);
    unix.extend(["CP_CACHE_DIR", "CCACHE_DIR"]);
    assert_eq!(names_on(MACOS, &config), unix);
    assert_eq!(names_on(LINUX, &config), unix);
}

#[test]
fn opt_in_tools_are_off_until_enabled_and_never_include_whole_homes_by_default() {
    let config = CacheConfig::default();
    for platform in PLATFORMS {
        let names = names_on(platform, &config);
        for home in [
            "CARGO_HOME",
            "GRADLE_USER_HOME",
            "MAVEN_ARGS",
            "POETRY_CACHE_DIR",
            "PUB_CACHE",
            "BUNDLE_USER_CACHE",
            // Never in the table at all: these would break zero-install Yarn
            // projects or move more than a cache.
            "YARN_CACHE_FOLDER",
            "DOTNET_CLI_HOME",
            "LOCALAPPDATA",
            "APPDATA",
        ] {
            assert!(
                !names.contains(&home),
                "{home} is on by default on {platform:?}"
            );
        }
    }
    let mut cargo = CacheConfig::default();
    cargo.tools.insert("cargo".into(), true);
    assert!(names_on(LINUX, &cargo).contains(&"CARGO_HOME"));
}

/// The values, per platform, with real separators: what a runner receives.
#[test]
fn values_point_into_the_namespace_or_the_slot_with_the_platforms_separator() {
    let root = std::env::temp_dir().join("rm-cache-values");
    let namespace = Namespace::of(&repo("Owner/Repo")).dir(&root);
    let slot = namespace.join(SLOTS_DIR).join("2");
    let mut config = CacheConfig::default();
    config.tools.insert("maven".into(), true);
    let selection = select(&config, &repo("Owner/Repo"), RunnerPlatform::current());
    let (variables, dirs) = environment(
        selection.enabled_tools(),
        &namespace,
        &slot,
        RunnerPlatform::current(),
    );
    let value = |name: &str| {
        variables
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| PathBuf::from(v))
            .unwrap_or_else(|| panic!("{name} missing"))
    };
    assert_eq!(namespace, root.join("owner").join("repo"));
    assert_eq!(value("npm_config_cache"), namespace.join("npm"));
    assert_eq!(value("npm_config_store_dir"), namespace.join("pnpm-store"));
    assert_eq!(value("PNPM_CONFIG_STORE_DIR"), namespace.join("pnpm-store"));
    assert_eq!(
        value("NUGET_PACKAGES"),
        namespace.join("nuget").join("packages")
    );
    assert_eq!(
        value("NUGET_SCRATCH"),
        namespace.join("nuget").join("scratch")
    );
    assert_eq!(value("GOMODCACHE"), namespace.join("go").join("mod"));
    assert_eq!(value("RUNNER_TOOL_CACHE"), slot.join("tool-cache"));
    assert_eq!(value("AGENT_TOOLSDIRECTORY"), slot.join("tool-cache"));
    assert_eq!(value("DOTNET_INSTALL_DIR"), slot.join("dotnet"));
    assert_eq!(value("CYPRESS_CACHE_FOLDER"), slot.join("cypress"));
    assert_eq!(value("PLAYWRIGHT_SKIP_BROWSER_GC"), PathBuf::from("1"));
    assert_eq!(
        value("MAVEN_ARGS"),
        PathBuf::from(format!(
            "-Dmaven.repo.local={}",
            slot.join("maven").display()
        ))
    );
    assert!(dirs.contains(&slot.join("tool-cache")));
    assert!(
        !dirs.iter().any(|dir| dir.ends_with("1")),
        "a literal value is not a directory"
    );
    if RunnerPlatform::current() == WINDOWS {
        assert!(!variables.iter().any(|(n, _)| *n == "XDG_CACHE_HOME"));
    } else {
        assert_eq!(value("XDG_CACHE_HOME"), namespace.join("xdg"));
    }
}

// -- selection and scoping ----------------------------------------------------

#[test]
fn a_repository_gets_its_own_namespace_and_an_organization_must_opt_in() {
    let config = CacheConfig::default();
    let own = select(&config, &repo("IvanMurzak/App"), LINUX);
    assert_eq!(own.disabled, None);
    assert_eq!(own.namespace.label(), "ivanmurzak/app");

    let other = select(&config, &repo("IvanMurzak/Other"), LINUX);
    assert_ne!(
        own.namespace, other.namespace,
        "two repositories never share by default"
    );

    let organization = select(&config, &org("Acme"), LINUX);
    assert_eq!(organization.disabled, Some(ORGANIZATION_OPT_IN));
    assert_eq!(organization.namespace.label(), "_org/acme");

    let mut opted = CacheConfig::default();
    opted.target_mut(&org("Acme")).enabled = Some(true);
    assert_eq!(select(&opted, &org("acme"), LINUX).disabled, None);
}

#[test]
fn sharing_is_explicit_and_names_the_same_directory_for_both_policies() {
    let mut config = CacheConfig::default();
    config.target_mut(&repo("a/one")).namespace = Some("js".into());
    config.target_mut(&repo("a/two")).namespace = Some("js".into());
    let one = select(&config, &repo("a/one"), MACOS);
    let two = select(&config, &repo("A/Two"), MACOS);
    assert_eq!(one.namespace, Namespace::Shared("js".into()));
    assert_eq!(
        one.namespace.dir(Path::new("/c")),
        two.namespace.dir(Path::new("/c"))
    );
    assert_eq!(
        select(&config, &repo("a/three"), MACOS).namespace.label(),
        "a/three"
    );
}

#[test]
fn host_switch_target_switch_and_tool_overrides_compose_in_order() {
    let mut config = CacheConfig::default();
    config.tools.insert("npm".into(), false);
    config.tools.insert("cargo".into(), true);
    config
        .target_mut(&repo("o/r"))
        .tools
        .insert("npm".into(), true);
    let state = |config: &CacheConfig, slug: &str, id: &str| {
        select(config, &repo(slug), LINUX)
            .tools
            .into_iter()
            .find(|state| state.tool.id == id)
            .map(|state| (state.enabled, state.source))
            .unwrap()
    };
    assert_eq!(state(&config, "o/r", "npm"), (true, ToolSource::Target));
    assert_eq!(state(&config, "o/other", "npm"), (false, ToolSource::Host));
    assert_eq!(state(&config, "o/other", "cargo"), (true, ToolSource::Host));
    assert_eq!(
        state(&config, "o/other", "pip"),
        (true, ToolSource::Default)
    );

    config.target_mut(&repo("o/r")).enabled = Some(false);
    assert_eq!(
        select(&config, &repo("o/r"), LINUX).disabled,
        Some("caches are turned off for this target")
    );
    config.target_mut(&repo("o/r")).enabled = Some(true);
    config.enabled = Some(false);
    assert_eq!(
        select(&config, &repo("o/r"), LINUX).disabled,
        Some("caches are turned off on this host"),
        "the host switch wins over a target that turned caches on"
    );
}

#[test]
fn namespace_segments_are_portable_path_segments() {
    assert_eq!(segment("con"), "con_");
    assert_eq!(segment("COM1.js"), "COM1.js_");
    assert_eq!(segment(".."), "_..");
    assert_eq!(segment("my.repo-name_2"), "my.repo-name_2");
    assert_eq!(
        Namespace::Shared("js".into()).dir(Path::new("/c")),
        Path::new("/c").join("_shared").join("js")
    );
}

// -- configuration ------------------------------------------------------------

#[test]
fn the_file_round_trips_and_drops_target_sections_that_say_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let path = config_path_in(directory.path());
    assert_eq!(CacheConfig::load(&path).unwrap(), CacheConfig::default());

    let mut config = CacheConfig {
        max_size_gib: Some(5),
        ..CacheConfig::default()
    };
    config.tools.insert("gradle".into(), true);
    config.target_mut(&repo("O/R")).namespace = Some("shared-js".into());
    config.target_mut(&repo("o/empty"));
    config.save(&path).unwrap();

    let loaded = CacheConfig::load(&path).unwrap();
    assert_eq!(loaded.max_bytes(), Some(5 * GIB));
    assert_eq!(loaded.tools.get("gradle"), Some(&true));
    assert!(loaded.targets.contains_key("o/r"));
    assert!(!loaded.targets.contains_key("o/empty"));
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("[targets.\"o/r\"]"), "{text}");
}

#[test]
fn a_bad_file_is_refused_with_what_is_wrong() {
    let path = Path::new("caches.toml");
    for (text, expected) in [
        ("unknown = 1\n", "unknown field"),
        (
            "[tools]\nnot-a-tool = true\n",
            "`not-a-tool` is not a cache",
        ),
        (
            "[targets.\"o/r\"]\nnamespace = \"Has Space\"\n",
            "not a valid shared namespace",
        ),
        (
            "[targets.\"not a target\"]\nenabled = true\n",
            "is not a repository",
        ),
        ("root = \"relative/dir\"\n", "absolute path without spaces"),
        (
            "root = \"/has space/cache\"\n",
            "absolute path without spaces",
        ),
    ] {
        let error = CacheConfig::parse(text, path).unwrap_err().to_string();
        assert!(error.contains(expected), "{text:?}: {error}");
    }
    assert_eq!(
        CacheConfig::parse("max_size_gib = 0\n", path)
            .unwrap()
            .max_bytes(),
        None
    );
    assert_eq!(
        CacheConfig::default().max_bytes(),
        Some(DEFAULT_MAX_SIZE_GIB * GIB)
    );
}

#[test]
fn the_root_is_configured_or_under_the_runner_root_and_never_has_spaces() {
    let configured = CacheConfig {
        root: Some("/srv/cache".into()),
        ..CacheConfig::default()
    };
    assert_eq!(
        resolve_root(&configured, Some(Path::new("/rman")), None)
            .unwrap()
            .source,
        RootSource::Configured
    );
    let default = CacheConfig::default();
    assert_eq!(
        resolve_root(&default, Some(Path::new("/Volumes/NVME/runners")), None).unwrap(),
        ResolvedRoot {
            path: Path::new("/Volumes/NVME/runners").join(DEFAULT_ROOT_NAME),
            source: RootSource::RunnerRoot
        }
    );
    // The macOS platform-default runner root sits under `Application Support`.
    let spaced = Path::new("/Users/me/Library/Application Support/rm/runtime");
    let fallback = std::env::temp_dir().join("rm-fallback");
    assert_eq!(
        resolve_root(&default, Some(spaced), Some(fallback.clone()))
            .unwrap()
            .source,
        RootSource::PlatformFallback
    );
    assert!(resolve_root(&default, Some(spaced), None).is_err());
    assert!(resolve_root(&default, Some(spaced), Some(PathBuf::from("/a b"))).is_err());
}

#[test]
fn a_value_the_service_environment_already_carries_is_left_alone() {
    // The WSL host's systemd drop-in sets DOTNET_INSTALL_DIR by hand.
    let variables = vec![
        (
            "DOTNET_INSTALL_DIR",
            OsString::from("/cache/o/r/_slots/1/dotnet"),
        ),
        ("npm_config_cache", OsString::from("/cache/o/r/npm")),
    ];
    let kept = without_inherited(variables, |name| name == "DOTNET_INSTALL_DIR");
    assert_eq!(
        kept,
        [("npm_config_cache", OsString::from("/cache/o/r/npm"))]
    );
    assert!(!inherited("RM_CACHE_TEST_SURELY_UNSET_VARIABLE"));
}

// -- launch -------------------------------------------------------------------

fn runtime_with_runner(parent: &Path, name: &str) -> PathBuf {
    let runtime = parent.join(name);
    fs::create_dir_all(runtime.join("bin")).unwrap();
    runtime
}

#[test]
fn a_launch_leases_the_lowest_free_slot_and_creates_its_directories() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("_cache");
    let selection = select(
        &CacheConfig::default(),
        &repo("o/r"),
        RunnerPlatform::current(),
    );
    let first = runtime_with_runner(directory.path(), "a1");
    let second = runtime_with_runner(directory.path(), "a2");

    let one = prepare_launch(
        &root,
        &selection,
        &first,
        RunnerPlatform::current(),
        &runtime_holds_runner,
    )
    .unwrap();
    let two = prepare_launch(
        &root,
        &selection,
        &second,
        RunnerPlatform::current(),
        &runtime_holds_runner,
    )
    .unwrap();
    assert_eq!((one.slot, two.slot), (1, 2), "a live lease is not shared");
    assert_eq!(one.namespace_dir, two.namespace_dir);
    assert!(one.namespace_dir.join("npm").is_dir());
    assert!(
        one.namespace_dir
            .join(SLOTS_DIR)
            .join("1")
            .join("tool-cache")
            .is_dir()
    );
    assert!(one.namespace_dir.join(LAST_USED_FILE).is_file());

    // The first attempt is cleaned: its package goes, and its slot is free.
    fs::remove_dir_all(&first).unwrap();
    let third = runtime_with_runner(directory.path(), "a3");
    let three = prepare_launch(
        &root,
        &selection,
        &third,
        RunnerPlatform::current(),
        &runtime_holds_runner,
    )
    .unwrap();
    assert_eq!(three.slot, 1);
}

// -- pruning ------------------------------------------------------------------

fn usage(name: &str, bytes: u64, age_secs: i64, in_use: bool) -> NamespaceUsage {
    NamespaceUsage {
        name: name.into(),
        bytes,
        last_used: Some(Utc::now() - chrono::Duration::seconds(age_secs)),
        in_use,
    }
}

#[test]
fn the_plan_removes_least_recently_used_idle_namespaces_until_the_total_fits() {
    let namespaces = [
        usage("o/new", 40, 10, false),
        usage("o/old", 30, 1000, false),
        usage("o/busy-oldest", 50, 5000, true),
        usage("o/middle", 20, 500, false),
    ];
    assert_eq!(plan_prune(&namespaces, Some(200)), Vec::<String>::new());
    assert_eq!(plan_prune(&namespaces, Some(110)), ["o/old"]);
    assert_eq!(plan_prune(&namespaces, Some(95)), ["o/old", "o/middle"]);
    // Even when nothing else fits, an in-use namespace is never planned.
    assert_eq!(
        plan_prune(&namespaces, Some(0)),
        ["o/old", "o/middle", "o/new"]
    );
    assert!(plan_prune(&namespaces, None).is_empty());
}

fn fill(dir: &Path, bytes: usize) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("blob"), vec![0_u8; bytes]).unwrap();
}

fn lease(namespace: &Path, slot: u32, runtime: &Path) {
    let slots = namespace.join(SLOTS_DIR);
    fs::create_dir_all(&slots).unwrap();
    fs::write(
        slots.join(format!("{slot}.{LEASE_EXTENSION}")),
        runtime.to_string_lossy().as_bytes(),
    )
    .unwrap();
}

fn age(namespace: &Path, secs: u64) {
    let marker = namespace.join(LAST_USED_FILE);
    fs::write(&marker, b"x").unwrap();
    let file = fs::File::options().write(true).open(&marker).unwrap();
    file.set_modified(SystemTime::now() - Duration::from_secs(secs))
        .unwrap();
}

#[test]
fn pruning_never_deletes_a_namespace_a_live_runner_holds() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("_cache");
    let busy = root.join("o").join("busy");
    let idle = root.join("o").join("idle");
    fill(&busy.join("npm"), 4096);
    fill(&idle.join("npm"), 4096);
    // The busy namespace is the least recently used, so a prune that ignored
    // leases would take it first.
    age(&busy, 10_000);
    age(&idle, 10);
    let live = runtime_with_runner(directory.path(), "live");
    lease(&busy, 1, &live);

    let report = prune(&root, Some(0), &runtime_holds_runner).unwrap();
    assert!(
        busy.join("npm").join("blob").is_file(),
        "an in-use namespace was pruned"
    );
    assert!(!idle.exists(), "the idle namespace should have gone");
    assert_eq!(report.pruned, ["o/idle"]);
    assert_eq!(CacheUsage::read(&root).unwrap().pruned, ["o/idle"]);

    // Once its attempt is cleaned, the same namespace is fair game.
    fs::remove_dir_all(&live).unwrap();
    let report = prune(&root, Some(0), &runtime_holds_runner).unwrap();
    assert_eq!(report.pruned, ["o/busy"]);
    assert!(!busy.exists());
    assert!(
        fs::read_dir(root.join(TRASH_DIR)).unwrap().next().is_none(),
        "pruned namespaces are deleted, not left in the trash"
    );
}

/// A launch that leases a namespace after the measurement but before the
/// rename keeps it: the rename re-checks under the lock.
#[test]
fn a_lease_taken_after_measuring_still_protects_the_namespace() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("_cache");
    let namespace = root.join("o").join("raced");
    fill(&namespace.join("pip"), 4096);
    let runtime = directory.path().join("racer");
    lease(&namespace, 1, &runtime);
    // Idle while measured, live by the time it is about to be moved.
    let calls = Cell::new(0);
    let holds = |_: &Path| {
        calls.set(calls.get() + 1);
        calls.get() > 1
    };
    let report = prune(&root, Some(0), &holds).unwrap();
    assert!(report.pruned.is_empty());
    assert!(namespace.join("pip").join("blob").is_file());
}

#[cfg(unix)]
#[test]
fn a_read_only_go_module_cache_is_still_pruned() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("_cache");
    let module = root
        .join("o")
        .join("go-user")
        .join("go")
        .join("mod")
        .join("x@v1");
    fill(&module, 128);
    fs::set_permissions(&module, fs::Permissions::from_mode(0o555)).unwrap();
    let report = prune(&root, Some(0), &runtime_holds_runner).unwrap();
    assert_eq!(report.pruned, ["o/go-user"]);
    assert!(!root.join("o").join("go-user").exists());
}

#[test]
fn measurement_ignores_the_roots_own_entries() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fill(&root.join(TRASH_DIR).join("x"), 10);
    fill(&root.join("o").join("r").join("npm"), 10);
    fs::write(root.join(USAGE_FILE), b"{}").unwrap();
    let measured = measure(root, &runtime_holds_runner);
    assert_eq!(
        measured
            .iter()
            .map(|ns| ns.name.as_str())
            .collect::<Vec<_>>(),
        ["o/r"]
    );
    assert_eq!(measured[0].bytes, 10);
}
