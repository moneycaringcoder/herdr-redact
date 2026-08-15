//! The findings store: what has been seen, what has been acknowledged, and what
//! has already been shouted about.
//!
//! STUB — owned by the `surface` builder. The signatures below are the contract
//! the rest of the crate compiles against; the bodies are placeholders.
//!
//! # Contract
//!
//! * Nothing written to disk may contain a secret. The store persists the
//!   pattern name, the pane, the masked preview, the length and the **keyed**
//!   digest — never the value.
//! * A finding stays until acknowledged. A secret that scrolled out of view is
//!   still in scrollback and still exposed.
//! * Acknowledgements persist across restarts. Re-warning about something the
//!   user already dismissed is the crying-wolf failure mode.
//! * A finding whose pane no longer exists is pruned: its scrollback died with
//!   the pane, so there is nothing left to warn about.
//! * Notifications are rate limited to one per pattern per pane per daemon run.

use crate::config::Config;
use crate::model::{DigestKey, Finding, Match, PaneRef, Report};
use crate::Result;

#[derive(Debug, Default)]
pub struct Store {
    key: DigestKey,
    findings: Vec<Finding>,
}

impl Store {
    /// Loads the persisted store, or an empty one. Best effort and never fails:
    /// an unreadable state file must not stop the scanner from running, though
    /// it must say so.
    pub fn load(_config: &Config) -> Self {
        Self::default()
    }

    /// The per-installation digest key, drawn on first use and persisted.
    pub fn key(&self) -> &DigestKey {
        &self.key
    }

    /// Folds one pane's matches into the store. Returns the findings that are
    /// new — the ones a notification would be about.
    pub fn observe(&mut self, _pane: &PaneRef, _matches: &[Match], _now: u64) -> Vec<Finding> {
        Vec::new()
    }

    /// Drops findings whose pane is no longer in the session.
    pub fn prune_to(&mut self, _live_pane_ids: &[String]) -> usize {
        0
    }

    /// Acknowledges by id or unambiguous id prefix. Returns how many were
    /// acknowledged; zero is an error at the call site, not here.
    pub fn acknowledge(&mut self, _id: &str) -> usize {
        0
    }

    pub fn acknowledge_all(&mut self) -> usize {
        0
    }

    /// Forgets everything, acknowledged or not. The state file is rewritten
    /// empty rather than deleted, so the digest key survives.
    pub fn forget_all(&mut self) -> usize {
        0
    }

    /// Whether a toast should be posted for this finding, and marks it shouted
    /// about. One per pattern per pane per daemon run.
    pub fn claim_notification(&mut self, _finding: &Finding) -> bool {
        false
    }

    /// Every finding, unacknowledged first, then most recently seen first.
    pub fn findings(&self) -> Vec<Finding> {
        self.findings.clone()
    }

    /// Builds the report the renderers consume.
    pub fn report(&self, notes: Vec<String>) -> Report {
        Report {
            findings: self.findings(),
            notes,
            generated_at: crate::model::now(),
            ..Report::default()
        }
    }

    pub fn save(&self) -> Result<()> {
        Ok(())
    }
}
