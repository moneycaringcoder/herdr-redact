//! Watcher lifecycle: detached daemon, pid/enabled markers, the scan cycle, TTL
//! badge pushes, and cleanup that survives being killed.
//!
//! STUB — owned by the `surface` builder. The signatures below are the contract
//! the rest of the crate compiles against; the bodies are placeholders. See
//! docs/herdr-protocol.md for the lifecycle contract these verbs implement, and
//! adapt `~/repos/herdr-collide/src/daemon.rs`, which implements it correctly.

use crate::config::Config;
use crate::findings::Store;
use crate::herdr::Herdr;
use crate::model::Report;
use crate::Result;

pub fn enable(_args: &[String]) -> Result<()> {
    Ok(())
}

pub fn disable() -> Result<()> {
    Ok(())
}

pub fn toggle(_args: &[String]) -> Result<()> {
    Ok(())
}

/// herdr startup hook. Silent no-op unless the enabled marker is set and no
/// daemon is currently live.
pub fn restore() -> Result<()> {
    Ok(())
}

/// The scan loop itself, running in the foreground.
pub fn run(_config: &Config) -> Result<()> {
    Ok(())
}

/// One full cycle over an existing client: snapshot, read each pane, scan, fold
/// into the store. Shared by the daemon and by the one-shot verbs, so they can
/// never disagree about what a scan is.
pub fn scan_cycle(_client: &mut Herdr, _config: &Config, _store: &mut Store) -> Result<Report> {
    Ok(Report::default())
}

/// One cycle over a fresh connection, for `--once` and `--json`.
pub fn scan_once(config: &Config) -> Result<Report> {
    let mut client = Herdr::connect()?;
    let mut store = Store::load(config);
    let report = scan_cycle(&mut client, config, &mut store)?;
    store.save()?;
    Ok(report)
}

pub fn live_pid() -> Option<i32> {
    None
}

pub fn is_enabled() -> bool {
    false
}
