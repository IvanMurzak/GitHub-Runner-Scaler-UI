mod support;
use support::{run, runner_manager};

#[test]
fn auto_update_defaults_and_explicit_preferences_round_trip() {
    let data = tempfile::tempdir().unwrap();
    let show = || {
        run({
            let mut c = runner_manager(data.path());
            c.args(["host", "show"]);
            c
        })
    };
    assert!(show().stdout.contains("Automatic daily updates: true"));
    for value in ["false", "true"] {
        let result = run({
            let mut c = runner_manager(data.path());
            c.args(["host", "set-auto-update", value]);
            c
        });
        assert_eq!(result.code, 0, "{}", result.both());
        assert!(
            show()
                .stdout
                .contains(&format!("Automatic daily updates: {value}"))
        );
        assert!(
            std::fs::read_to_string(data.path().join("config/updates.toml"))
                .unwrap()
                .contains(&format!("enabled = {value}"))
        );
    }
}
#[test]
fn invalid_auto_update_value_preserves_preference() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("config/updates.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "enabled = false\n").unwrap();
    let result = run({
        let mut c = runner_manager(data.path());
        c.args(["host", "set-auto-update", "maybe"]);
        c
    });
    assert_eq!(result.code, 2);
    assert_eq!(std::fs::read_to_string(path).unwrap(), "enabled = false\n");
}
