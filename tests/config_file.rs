//! What the config loader does with a key it does not know.
//!
//! The assertion here is that an unknown key is *ignored*, not rejected. A
//! config file is edited by hand, so a typo in one — or a key that a later
//! version stopped reading — must never be able to stop the scanner: it loads
//! the keys it understands, drops the rest, and runs.
//!
//! `entropy` is the concrete case. It used to be a real key that did nothing;
//! now it is not a key at all, and a file that still sets it has to load
//! exactly like a file with any other stray key in it.
//!
//! This test mutates `HERDR_PLUGIN_CONFIG_DIR`, which is process-wide. It is
//! the only test in this binary for that reason, and it must stay that way:
//! cargo runs the tests within one binary on several threads, so a second test
//! here that read a config path could see this one's directory. Other test
//! binaries are separate processes and cannot be affected.

use redact::config::Config;

#[test]
fn a_config_that_still_sets_entropy_loads_and_is_ignored() {
    let dir = std::env::temp_dir().join(format!("redact-config-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    // `lines` is here so a load that silently skipped the file cannot pass.
    std::fs::write(
        dir.join("config.json"),
        br#"{"entropy": true, "lines": 800}"#,
    )
    .expect("config file");

    std::env::set_var("HERDR_PLUGIN_CONFIG_DIR", &dir);

    let loaded = redact::config::load();
    let _ = std::fs::remove_dir_all(&dir);

    let config = loaded.expect("an unknown key must not fail the load");
    assert_eq!(config.lines, 800, "the config file was not read");
    let defaults = Config::default();
    assert_eq!(config.interval, defaults.interval);
    assert_eq!(config.notify, defaults.notify);
    assert_eq!(config.env_assignments, defaults.env_assignments);
}
