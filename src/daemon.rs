//! Watcher lifecycle: detached daemon, pid/enabled markers, the scan cycle, TTL
//! badge pushes, and cleanup that survives being killed. See
//! docs/herdr-protocol.md for the lifecycle contract these verbs implement.

use std::collections::HashMap;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{self, Config};
use crate::findings::Store;
use crate::herdr::{self, Herdr};
use crate::model::{Alert, Calibration, CalibrationHit, DigestKey, PaneRef, Report};
use crate::scan::{self, Rules};
use crate::{render, Result};

/// The stop request only posts a signal; the daemon still has to clear its
/// badges. Bounded so `--disable` can never hang on a wedged daemon.
const STOP_TIMEOUT: Duration = Duration::from_secs(3);
const STOP_POLL: Duration = Duration::from_millis(25);

/// The main loop wakes at least this often so a stop request is noticed
/// promptly even with a long scan interval.
const LOOP_TICK: Duration = Duration::from_millis(250);

/// Valued arguments the detached child is given a copy of. It re-reads the
/// config file but never sees the user's command line, so `redact --enable
/// --lines 2000` would otherwise run at the config file's budget.
const FORWARDED_VALUES: [&str; 2] = ["--interval", "--lines"];

/// Flags forwarded as-is, with no value of their own.
const FORWARDED_FLAGS: [&str; 1] = ["--all-panes"];

pub fn enable(args: &[String]) -> Result<()> {
    // Parse before touching any state: a typo'd value must fail here, where the
    // user can see it, and not inside a detached child whose stderr is
    // /dev/null.
    let forwarded = forwarded_args(args)?;
    config::load_with_args(args)?;

    // Mark next. If the spawn fails, or the server hands off before we finish,
    // `--restore` still knows the user wants a daemon.
    mark_enabled(true);
    if live_pid().is_some() {
        return Ok(());
    }
    spawn_detached(&forwarded)
}

pub fn disable() -> Result<()> {
    // Mark first, so nothing that observes the markers mid-teardown concludes
    // the daemon is still wanted.
    mark_enabled(false);

    if let Some(pid) = live_pid() {
        request_stop(pid);
        // Load-bearing: the stop request only posts, and the pid file lives
        // until the daemon has finished clearing. An `--enable` landing in that
        // window would see a live pid, spawn nothing, and the badge would never
        // come back.
        if !await_exit(pid, STOP_TIMEOUT) {
            eprintln!("redact: watcher {pid} did not exit within {STOP_TIMEOUT:?}");
        }
    }
    clear_pid_file();

    // Fresh connection, and every current pane and workspace: the daemon may
    // have died without clearing, and it only ever tracked what it had lit.
    let mut client = Herdr::connect()?;
    sweep(&mut client)
}

pub fn toggle(args: &[String]) -> Result<()> {
    if live_pid().is_some() {
        disable()
    } else {
        enable(args)
    }
}

/// herdr startup hook. Silent no-op unless the enabled marker is set and no
/// daemon is currently live.
pub fn restore() -> Result<()> {
    if !is_enabled() || live_pid().is_some() {
        return Ok(());
    }
    // A startup hook has no user command line to forward; the child falls back
    // to the config file, which is the only durable record of the user's
    // choices anyway.
    spawn_detached(&[])
}

/// The scan loop itself, running in the foreground.
///
/// Takes the command line rather than a `Config` because it re-reads the config
/// file every cycle. A watcher enabled once and left running for a week would
/// otherwise still be using the rules it started with, while `redact --rules`
/// in a shell reported the new ones as active — a user could edit
/// `config.json`, see their pattern listed, and never be protected by it.
pub fn run(args: &[String]) -> Result<()> {
    let mut config = config::load_with_args(args)?;
    write_pid(std::process::id());

    // Which token name is currently lit per target. A severity flip has to
    // clear the old name before setting the new one, or herdr renders two
    // badges at once — the merge patch only touches names we mention.
    let active = Arc::new(Mutex::new(ActiveBadges::default()));
    let stopping = Arc::new(AtomicBool::new(false));
    spawn_signal_thread(Arc::clone(&active), Arc::clone(&stopping))?;

    let mut store = Store::load(&config);
    let mut client: Option<Herdr> = None;
    // Notes repeat every cycle for as long as their cause lasts, so only the
    // ones that are new since the last cycle are worth printing.
    let mut reported_notes: Vec<String> = Vec::new();

    loop {
        if stopping.load(Ordering::SeqCst) {
            // The signal thread owns shutdown from here: it clears state over
            // its own connection and exits the process. Park rather than
            // return, so this thread can never push a badge back on top of the
            // clear it is racing.
            loop {
                std::thread::park();
            }
        }

        // Config first, so a pattern added to the file is in force this cycle
        // rather than after a restart. A file that has become malformed is a
        // warning from `config::load_file` and the defaults, never a reason to
        // stop scanning; only a command line we can no longer parse is fatal,
        // and that cannot change under a running process.
        match config::load_with_args(args) {
            Ok(reloaded) => config = reloaded,
            Err(err) => eprintln!("redact: keeping the previous configuration: {err}"),
        }

        if client.is_none() {
            match Herdr::connect() {
                Ok(connected) => client = Some(connected),
                Err(err) => eprintln!("redact: cannot reach herdr: {err}"),
            }
        }
        if let Some(connected) = client.as_mut() {
            // Picks up an acknowledgement made from a shell since the last
            // cycle, so this run's save cannot undo it.
            store.reload_if_changed(&config);

            match scan_cycle_with_panes(connected, &config, &mut store) {
                Ok((report, panes)) => {
                    for note in new_notes(&reported_notes, &report.notes) {
                        eprintln!("redact: {note}");
                    }
                    reported_notes.clone_from(&report.notes);

                    notify_new(connected, &config, &panes, &mut store);
                    push(connected, &config, &report, &panes, &active);

                    if let Err(err) = store.save() {
                        eprintln!("redact: could not save findings: {err}");
                    }
                }
                Err(err) => {
                    eprintln!("redact: scan failed: {err}");
                    // Only a transport failure is worth redialling for; an error
                    // envelope means the server is fine and answered us.
                    if herdr::error_code(&*err).is_none() {
                        client = None;
                    }
                }
            }
        }

        nap(config.interval, &stopping);
    }
}

// ---------------------------------------------------------------------------
// The scan cycle
// ---------------------------------------------------------------------------

/// Compile the rules used by every scanning path, preserving warnings that
/// would otherwise make a degraded rule set look complete.
///
/// Notes are de-duplicated because overlays mean this is called once per
/// distinct effective configuration rather than once per cycle. Two panes whose
/// overlays both carry the same bad regex are one problem, and reporting it
/// twice would suggest two.
fn rules_for_scan(config: &Config, notes: &mut Vec<String>) -> Rules {
    // A rule the user typed that will not compile is fatal for `--rules`, where
    // they are looking right at it. A scanning path must not stop protecting
    // every built-in format because one configured regex is bad.
    let rules = match Rules::compile(config) {
        Ok(rules) => rules,
        Err(err) => {
            let note = format!(
                "a configured pattern did not compile ({err}); scanning with the built-in rules \
                 only — the rules you added are NOT active"
            );
            if !notes.contains(&note) {
                notes.push(note);
            }
            Rules::builtin()
        }
    };
    // A setting the user believes is protecting them and is not is exactly the
    // kind of silence this plugin cannot afford. `config.notes` carries what the
    // overlay parser had to say, which is the same class of silence.
    for note in config.notes.iter().chain(&rules.notes) {
        if !notes.contains(note) {
            notes.push(note.clone());
        }
    }
    rules
}

/// One full cycle over an existing client: snapshot, read each pane, scan, fold
/// into the store. Shared by the daemon and by the one-shot verbs, so they can
/// never disagree about what a scan is.
pub fn scan_cycle(client: &mut Herdr, config: &Config, store: &mut Store) -> Result<Report> {
    Ok(scan_cycle_with_panes(client, config, store)?.0)
}

/// [`scan_cycle`], also handing back the panes the snapshot reported.
///
/// The daemon needs them to plan badges, and taking a second snapshot for that
/// would be a round trip per cycle spent asking a question we just asked.
pub fn scan_cycle_with_panes(
    client: &mut Herdr,
    config: &Config,
    store: &mut Store,
) -> Result<(Report, Vec<PaneRef>)> {
    scan_cycle_within(client, config, store, config.cycle_budget())
}

/// [`scan_cycle_with_panes`] with an explicit reading budget.
///
/// Exists so the round-robin can be tested in milliseconds rather than in the
/// thirty seconds [`Config::cycle_budget`] floors at. Production callers use the
/// derived budget; nothing else should pass one.
pub fn scan_cycle_within(
    client: &mut Herdr,
    config: &Config,
    store: &mut Store,
    budget: Duration,
) -> Result<(Report, Vec<PaneRef>)> {
    let panes = client.panes()?;
    let now = crate::model::now();
    let mut notes = Vec::new();

    // Cache entries are keyed by the complete effective Config, never by pane
    // identity or matcher. Equal effective configurations share compilation;
    // different overlays therefore cannot leak a rule set across panes.
    let base_config = config.base();
    let base_rules = rules_for_scan(&base_config, &mut notes);
    let mut rule_sets = HashMap::from([(base_config, base_rules)]);

    // A findings pane that scans itself reports its own masked previews for
    // ever, and every one of them looks like a real finding.
    let own_pane = config::non_empty_env("HERDR_PANE_ID");

    let mut scanned = 0usize;
    let mut truncated = 0usize;
    let mut failed = 0usize;
    let mut unread = 0usize;

    // Split before reading, so the rotation below is over panes we actually mean
    // to read rather than over the whole session.
    let (readable, skipped): (Vec<&PaneRef>, Vec<&PaneRef>) = panes.iter().partition(|pane| {
        if config.overlays.is_empty() {
            should_scan(pane, config, own_pane.as_deref())
        } else {
            let effective = config.effective_for(pane);
            should_scan(pane, &effective, own_pane.as_deref())
        }
    });
    let skipped = skipped.len();

    // A cycle has to finish. Reading is one round trip per pane, and on a busy
    // session with thirty panes a slow server can put the total well past any
    // sane interval — at which point the badge is never pushed at all, because
    // the cycle that would have pushed it has not returned yet.
    //
    // Observed live rather than imagined: with twenty agents running, single
    // reads exceeded the socket's own 15-second timeout and the whole cycle
    // failed, leaving findings in the store and no badge on the sidebar.
    let deadline = Instant::now() + budget;

    // Start where the last cycle stopped. Without this the budget would cut the
    // list at the same place every time: the first handful of panes read for
    // ever and the tail never read at all, which is a permanent blind spot
    // reported as a clean session.
    let start = store.scan_cursor(readable.len());
    let mut cursor = start;

    for offset in 0..readable.len() {
        let index = (start + offset) % readable.len();
        let pane = readable[index];
        if Instant::now() >= deadline {
            unread += 1;
            continue;
        }
        cursor = (index + 1) % readable.len();
        let effective_owned = (!config.overlays.is_empty()).then(|| config.effective_for(pane));
        let effective = effective_owned.as_ref().unwrap_or(config);
        // Backfill depth is a scalar like any other, so an overlay may set it:
        // a repository whose panes hold a long history can ask for a deeper
        // first read without changing what every other workspace does.
        let backfill = effective.backfill_lines > 0 && store.needs_backfill(&pane.pane_id);
        let lines = if backfill {
            effective.backfill_lines
        } else {
            effective.lines
        };
        let rules = if let Some(rules) = rule_sets.get(effective) {
            rules
        } else {
            let compiled = rules_for_scan(effective, &mut notes);
            rule_sets.entry(effective.clone()).or_insert(compiled)
        };
        let text = match client.read_pane(&pane.pane_id, lines) {
            Ok(text) => text,
            Err(err) => {
                // An error envelope means the server is healthy and told us
                // something: a pane that closed under us is data, not a
                // failure.
                //
                // A transport failure used to propagate here, on the reasoning
                // that we are blind and must say so. Live running showed that
                // to be the wrong call: one slow pane read then costs every
                // other pane its badge, and the cycle that would have reported
                // the failure never completes. The snapshot call above is the
                // real liveness check — if the server is genuinely gone, it
                // fails first and this loop is never reached.
                failed += 1;
                match herdr::error_code(&*err) {
                    Some("pane_not_found") => notes.push(format!(
                        "pane {} closed while it was being read",
                        pane.pane_id
                    )),
                    _ => notes.push(format!("pane {} could not be read: {err}", pane.pane_id)),
                }
                continue;
            }
        };
        // Marked only now the read has come back. Claiming it before the call
        // would spend the pane's one deep read on a transport error or a pane
        // that closed under us: that pane would be treated as backfilled for the
        // life of the process, its scrollback would never be scanned, and the
        // blind spot would render as a permanently clean pane.
        if backfill {
            store.mark_backfilled(&pane.pane_id);
        }

        scanned += 1;
        if text.truncated {
            if backfill {
                notes.push(format!(
                    "pane {} startup backfill was truncated at its {}-line history budget; older \
                     scrollback was not scanned",
                    pane.pane_id, lines
                ));
            } else {
                truncated += 1;
                notes.push(format!(
                    "pane {} had more output than the {}-line budget; anything above it was not \
                     scanned",
                    pane.pane_id, lines
                ));
            }
        }

        // Trap 3: `PaneReadResult.revision` is always zero on the wire, so
        // change detection has to come from the text. A cache hit skips the
        // scan and nothing else — the pane's existing findings stay exactly
        // where they are.
        if store.pane_text_changed(&pane.pane_id, &text.text) {
            // `scan_reporting` rather than `scan`: a rule that hit its ceiling
            // stopped looking, and a scan that stopped looking must be able to
            // say so. Silence there would mean a flood of weak matches in one
            // pane could hide a real key with nothing to show for it.
            let scanned = scan::scan_reporting(&text.text, rules, store.key());
            for note in scanned.notes {
                notes.push(format!("pane {}: {note}", pane.pane_id));
            }
            let fresh = store.observe(pane, &scanned.matches, now);
            // Process context costs another socket round trip, so only ask for
            // it after this pane produced a finding that did not already exist.
            // It is useful context, not scan coverage: failure is deliberately
            // silent and never costs the pane its finding or badge.
            if !fresh.is_empty() {
                if let Ok(process) = client.process_info(&pane.pane_id) {
                    if process.pane_id == pane.pane_id {
                        store.record_foreground_process_when_first_seen(
                            &fresh,
                            process.foreground_process_name.as_deref(),
                            process.foreground_process_pid,
                        );
                    }
                }
            }
        }
    }

    store.set_scan_cursor(cursor);

    if unread > 0 {
        notes.push(format!(
            "{unread} pane(s) were not read before this cycle's {budget:?} budget ran out; the \
             next cycle starts where this one stopped, so they are read then"
        ));
    }
    // Every read failing is a different thing from a few failing, and it is the
    // shape a wedged or overloaded server takes. Say so in one line rather than
    // leaving the user to count the per-pane notes.
    if failed > 0 && scanned == 0 {
        notes.push(
            "every pane read failed, so nothing was scanned this cycle — the findings below are \
             from an earlier one"
                .to_string(),
        );
    }

    let live: Vec<String> = panes.iter().map(|pane| pane.pane_id.clone()).collect();
    store.prune_to(&live);

    let mut report = store.report(notes);
    report.panes_scanned = scanned;
    report.panes_skipped = skipped;
    report.panes_unread = failed + unread;
    report.panes_truncated = truncated;
    Ok((report, panes))
}

/// One cycle over a fresh connection, for `--once` and `--json`.
///
/// These interactive verbs use the ordinary window rather than making the user
/// wait for the watcher's startup scrollback backfill.
pub fn scan_once(config: &Config) -> Result<Report> {
    let mut client = Herdr::connect()?;
    let mut store = Store::load(config);
    let mut one_shot = config.clone();
    one_shot.backfill_lines = 0;
    let report = scan_cycle(&mut client, &one_shot, &mut store)?;
    store.save()?;
    Ok(report)
}

/// Run the active rules over one snapshot without creating persistent state or
/// mutating anything in herdr.
pub fn calibrate(config: &Config) -> Result<Calibration> {
    let mut client = Herdr::connect()?;
    let panes = client.panes()?;
    let generated_at = crate::model::now();
    let mut notes = Vec::new();
    let rules = rules_for_scan(config, &mut notes);
    let own_pane = config::non_empty_env("HERDR_PANE_ID");

    let (readable, skipped): (Vec<&PaneRef>, Vec<&PaneRef>) = panes
        .iter()
        .partition(|pane| should_scan(pane, config, own_pane.as_deref()));
    let panes_skipped = skipped.len();
    let budget = config.cycle_budget();
    let deadline = Instant::now() + budget;
    let mut hits = Vec::new();
    let mut panes_scanned = 0usize;
    let mut panes_truncated = 0usize;
    let mut failed = 0usize;
    let mut unread = 0usize;

    // Calibration has no store to remember a cursor and no later cycle to make
    // up missed work, so its single snapshot starts at the first readable pane.
    //
    // A zero key is correct here only: calibration has no cycles and nothing
    // to recognise across them. Reusing it anywhere persistent would turn the
    // digest into a guessing oracle.
    let digest_key: DigestKey = [0; 16];
    for pane in readable {
        if Instant::now() >= deadline {
            unread += 1;
            continue;
        }
        let text = match client.read_pane(&pane.pane_id, config.lines) {
            Ok(text) => text,
            Err(err) => {
                failed += 1;
                match herdr::error_code(&*err) {
                    Some("pane_not_found") => notes.push(format!(
                        "pane {} closed while it was being read",
                        pane.pane_id
                    )),
                    _ => notes.push(format!("pane {} could not be read: {err}", pane.pane_id)),
                }
                continue;
            }
        };

        panes_scanned += 1;
        if text.truncated {
            panes_truncated += 1;
            notes.push(format!(
                "pane {} had more output than the {}-line budget; anything above it was not \
                 scanned",
                pane.pane_id, config.lines
            ));
        }

        let scanned = scan::scan_reporting(&text.text, &rules, &digest_key);
        for note in scanned.notes {
            notes.push(format!("pane {}: {note}", pane.pane_id));
        }
        hits.extend(scanned.matches.into_iter().map(|matched| CalibrationHit {
            pane_id: pane.pane_id.clone(),
            pane_label: pane.label().to_string(),
            workspace_id: pane.workspace_id.clone(),
            matched,
        }));
    }

    if unread > 0 {
        notes.push(format!(
            "{unread} pane(s) were not read before this calibration's {budget:?} budget ran out; \
             calibration has no later cycle, so this result is incomplete"
        ));
    }
    if failed > 0 && panes_scanned == 0 {
        notes.push("every pane read failed, so nothing was scanned during calibration".to_string());
    }

    Ok(Calibration {
        hits,
        panes_scanned,
        panes_skipped,
        panes_unread: failed + unread,
        panes_truncated,
        notes,
        generated_at,
    })
}

/// Whether this pane's output should be read at all.
///
/// Pure, so the filter that decides what this plugin is allowed to look at can
/// be read and tested in one place rather than inferred from a loop.
pub fn should_scan(pane: &PaneRef, config: &Config, own_pane: Option<&str>) -> bool {
    if Some(pane.pane_id.as_str()) == own_pane {
        return false;
    }
    if config.ignore_panes.iter().any(|id| id == &pane.pane_id) {
        return false;
    }
    config.scan_all_panes || pane.agent.is_some()
}

/// Notes that were not already reported on the previous cycle. A note repeats
/// for as long as its cause lasts — a truncated pane produces one every few
/// seconds — so only the new ones are worth printing.
pub fn new_notes(previous: &[String], current: &[String]) -> Vec<String> {
    current
        .iter()
        .filter(|note| !previous.contains(note))
        .cloned()
        .collect()
}

/// Toasts findings seen for the first time, at most one per pattern per pane
/// per daemon run.
///
/// The queue is drained whether or not notifications are on, so turning them
/// off does not build a backlog that fires the moment they are turned back on.
fn notify_new(client: &mut Herdr, config: &Config, panes: &[PaneRef], store: &mut Store) {
    let fresh = store.take_new_findings();
    for finding in fresh {
        let notify = panes
            .iter()
            .find(|pane| pane.pane_id == finding.pane_id)
            .map_or(config.notify, |pane| {
                if config.overlays.is_empty() {
                    config.notify
                } else {
                    config.effective_for(pane).notify
                }
            });
        if !notify || !store.claim_notification(&finding) {
            continue;
        }
        let (title, body) = toast(&finding);
        if let Err(err) = client.notify(&title, &body) {
            eprintln!("redact: notification failed: {err}");
        }
    }
}

/// Title and body of the toast for one finding.
///
/// A toast body is the single easiest place in the whole plugin to leak a
/// credential: it is a string built by hand, it goes somewhere the user can see
/// but the test suite cannot, and it is the one output nobody re-reads. So it is
/// a named, public function rather than an inline `format!` — `tests/never_leaks.rs`
/// asserts against it directly.
///
/// Deliberately: the rule, the pane, the masked preview, the length, and the id
/// to dismiss it with. `Finding` has no field that could carry the value.
pub fn toast(finding: &crate::model::Finding) -> (String, String) {
    (
        format!("redact: {} in {}", finding.label, finding.pane_label),
        format!(
            "{} in {}: {} ({} chars). Dismiss with `redact --ack {}`.",
            finding.pattern,
            finding.pane_label,
            finding.preview,
            finding.value_len,
            finding.short_id()
        ),
    )
}

// ---------------------------------------------------------------------------
// Badges
// ---------------------------------------------------------------------------

/// Which token name this plugin currently has lit, per target.
///
/// Two maps rather than one because a pane id and a workspace id are different
/// namespaces, and clearing the wrong one leaves a badge nobody can explain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveBadges {
    pub panes: HashMap<String, String>,
    pub workspaces: HashMap<String, String>,
}

/// One badge call to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadgeOp {
    ClearPane {
        pane_id: String,
        token: String,
    },
    SetPane {
        pane_id: String,
        token: &'static str,
        text: String,
    },
    ClearWorkspace {
        workspace_id: String,
        token: String,
    },
    SetWorkspace {
        workspace_id: String,
        token: &'static str,
        text: String,
    },
}

/// Turns "what is lit now" plus "what this cycle found" into the calls that
/// close the gap. Pure, so the ordering rules below are testable without a
/// socket:
///
/// * A severity flip clears the old token name *before* setting the new one.
///   Tokens are a merge patch, so an unmentioned name stays lit and herdr would
///   render two badges for one target.
/// * `render::badge` is the single author of badge text, and it renders a clear
///   target as the empty string. An empty value is a clear, never a draw:
///   setting it would occupy the row with nothing.
/// * A target that dropped out of the report — pane closed, finding
///   acknowledged — is cleared rather than left to expire.
/// * Both the pane and its workspace are badged. An agent panel can be
///   collapsed, and a badge nobody can see protects nobody.
pub fn badge_plan(active: &ActiveBadges, report: &Report, panes: &[PaneRef]) -> Vec<BadgeOp> {
    badge_plan_with(active, report, panes, render::badge)
}

/// [`badge_plan`] with the badge text supplied by the caller.
///
/// Exists so the ordering rules can be tested against the text contract rather
/// than against whatever `render::badge` happens to produce today.
pub fn badge_plan_with(
    active: &ActiveBadges,
    report: &Report,
    panes: &[PaneRef],
    text_of: impl Fn(Alert, usize) -> String,
) -> Vec<BadgeOp> {
    let mut ops = Vec::new();

    let mut pane_ids: Vec<&str> = panes.iter().map(|pane| pane.pane_id.as_str()).collect();
    pane_ids.sort_unstable();
    pane_ids.dedup();

    // A pane may arrive with no workspace id — herdr reports absent context as
    // an empty string. Such a pane is still scanned and still badged as a pane;
    // it just has no workspace row to light, and asking herdr to report metadata
    // for workspace "" would be a rejected call every cycle.
    let mut workspace_ids: Vec<&str> = panes
        .iter()
        .map(|p| p.workspace_id.as_str())
        .filter(|id| !id.is_empty())
        .collect();
    workspace_ids.sort_unstable();
    workspace_ids.dedup();

    plan_target(
        &active.panes,
        &pane_ids,
        |id| report.alert_for_pane(id),
        &text_of,
        |pane_id, token| BadgeOp::ClearPane {
            pane_id: pane_id.to_string(),
            token: token.to_string(),
        },
        |pane_id, token, text| BadgeOp::SetPane {
            pane_id: pane_id.to_string(),
            token,
            text,
        },
        &mut ops,
    );
    plan_target(
        &active.workspaces,
        &workspace_ids,
        |id| report.alert_for_workspace(id),
        &text_of,
        |workspace_id, token| BadgeOp::ClearWorkspace {
            workspace_id: workspace_id.to_string(),
            token: token.to_string(),
        },
        |workspace_id, token, text| BadgeOp::SetWorkspace {
            workspace_id: workspace_id.to_string(),
            token,
            text,
        },
        &mut ops,
    );

    ops
}

/// The plan for one kind of target. Both kinds follow identical rules, and one
/// implementation is how they stay identical.
fn plan_target(
    active: &HashMap<String, String>,
    ids: &[&str],
    alert_of: impl Fn(&str) -> (Alert, usize),
    text_of: &impl Fn(Alert, usize) -> String,
    clear: impl Fn(&str, &str) -> BadgeOp,
    set: impl Fn(&str, &'static str, String) -> BadgeOp,
    ops: &mut Vec<BadgeOp>,
) {
    let mut wanted: Vec<&str> = Vec::new();

    for id in ids {
        let (alert, count) = alert_of(id);
        let text = text_of(alert, count);
        let next = if text.is_empty() {
            None
        } else {
            Some(alert.token_name())
        };
        let previous = active.get(*id).map(String::as_str);

        if let Some(previous) = previous {
            if Some(previous) != next {
                ops.push(clear(id, previous));
            }
        }
        if let Some(token) = next {
            wanted.push(id);
            // Re-sent every cycle even when unchanged: the TTL is what makes
            // the badge self-heal, and it only refreshes on a write.
            ops.push(set(id, token, text));
        }
    }

    // Targets we lit that this cycle has nothing to say about — a pane that
    // closed, a finding that was acknowledged — are cleared rather than left to
    // expire. A HashMap iterates arbitrarily, so the leftovers are sorted to
    // keep the plan reproducible for both tests and logs.
    let mut stale: Vec<(&String, &String)> = active
        .iter()
        .filter(|(id, _)| !wanted.contains(&id.as_str()))
        // Anything in `ids` was already handled above, including its clear.
        .filter(|(id, _)| !ids.contains(&id.as_str()))
        .collect();
    stale.sort();
    for (id, token) in stale {
        ops.push(clear(id, token));
    }
}

/// Executes a badge plan. Errors are reported per call and the cycle continues:
/// a swallowed push failure renders as a blank badge with nothing to debug, and
/// one bad pane must not cost every other one its badge.
fn push(
    client: &mut Herdr,
    config: &Config,
    report: &Report,
    panes: &[PaneRef],
    active: &Mutex<ActiveBadges>,
) {
    let ttl_ms = config.ttl_ms();
    let plan = badge_plan(&lock(active).clone(), report, panes);
    let mut lit = ActiveBadges::default();

    for op in plan {
        match op {
            // A failed clear is forgotten rather than retried next cycle: the
            // TTL expires it within three cycles anyway, and retrying forever
            // would hammer a target that no longer exists.
            BadgeOp::ClearPane { pane_id, token } => {
                cleared(client.clear_pane_badge(&pane_id, &token), &pane_id, &token);
            }
            BadgeOp::ClearWorkspace {
                workspace_id,
                token,
            } => {
                cleared(
                    client.clear_workspace_badge(&workspace_id, &token),
                    &workspace_id,
                    &token,
                );
            }
            BadgeOp::SetPane {
                pane_id,
                token,
                text,
            } => {
                if was_set(
                    client.set_pane_badge(&pane_id, token, &text, ttl_ms),
                    &pane_id,
                    token,
                ) {
                    lit.panes.insert(pane_id, token.to_string());
                }
            }
            BadgeOp::SetWorkspace {
                workspace_id,
                token,
                text,
            } => {
                if was_set(
                    client.set_workspace_badge(&workspace_id, token, &text, ttl_ms),
                    &workspace_id,
                    token,
                ) {
                    lit.workspaces.insert(workspace_id, token.to_string());
                }
            }
        }
    }

    *lock(active) = lit;
}

/// Whether a target is definitely not lit after a clear. A target that closed
/// under us has nothing lit on it either, and is expected churn rather than
/// something to shout about.
fn cleared(result: Result<()>, target: &str, token: &str) -> bool {
    match result {
        Ok(()) => true,
        Err(err) => {
            let gone = target_is_gone(&*err);
            if !gone {
                eprintln!("redact: clearing {token} on {target} failed: {err}");
            }
            gone
        }
    }
}

/// Whether a badge is now lit. A failed set is logged and not recorded, so the
/// next cycle tries again rather than believing in a badge that is not there.
fn was_set(result: Result<()>, target: &str, token: &str) -> bool {
    match result {
        Ok(()) => true,
        Err(err) => {
            if !target_is_gone(&*err) {
                eprintln!("redact: setting {token} on {target} failed: {err}");
            }
            false
        }
    }
}

fn target_is_gone(err: &(dyn std::error::Error + 'static)) -> bool {
    matches!(
        herdr::error_code(err),
        Some("pane_not_found") | Some("workspace_not_found")
    )
}

/// Clears every token this plugin owns on every current pane and workspace.
///
/// Total rather than tracked: the daemon may have died without clearing, and it
/// only ever knew about the targets it had lit itself. Clearing a name that was
/// never set costs one round trip and cannot go stale.
fn sweep(client: &mut Herdr) -> Result<()> {
    let panes = client.panes()?;
    let mut workspaces: Vec<&str> = panes.iter().map(|p| p.workspace_id.as_str()).collect();
    workspaces.sort_unstable();
    workspaces.dedup();

    let mut failures = 0usize;
    for pane in &panes {
        for token in Alert::ALL_TOKENS {
            if !cleared(
                client.clear_pane_badge(&pane.pane_id, token),
                &pane.pane_id,
                token,
            ) {
                failures += 1;
            }
        }
    }
    for workspace_id in workspaces {
        for token in Alert::ALL_TOKENS {
            if !cleared(
                client.clear_workspace_badge(workspace_id, token),
                workspace_id,
                token,
            ) {
                failures += 1;
            }
        }
    }
    if failures > 0 {
        return Err(format!("{failures} badge clears failed; see the messages above").into());
    }
    Ok(())
}

fn spawn_signal_thread(active: Arc<Mutex<ActiveBadges>>, stopping: Arc<AtomicBool>) -> Result<()> {
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
    ])?;
    std::thread::spawn(move || {
        if signals.forever().next().is_some() {
            stopping.store(true, Ordering::SeqCst);
            shutdown(&active);
            std::process::exit(0);
        }
    });
    Ok(())
}

/// Clears everything this daemon lit, over its **own** connection so it never
/// waits on the main loop's sleep or its in-flight round trip.
fn shutdown(active: &Mutex<ActiveBadges>) {
    let tracked = lock(active).clone();
    match Herdr::connect() {
        Ok(mut client) => {
            for (pane_id, token) in &tracked.panes {
                cleared(client.clear_pane_badge(pane_id, token), pane_id, token);
            }
            for (workspace_id, token) in &tracked.workspaces {
                cleared(
                    client.clear_workspace_badge(workspace_id, token),
                    workspace_id,
                    token,
                );
            }
        }
        // Not silent: without this line a killed daemon looks like it cleaned
        // up, and the badge lingers until its TTL expires.
        Err(err) => eprintln!("redact: shutdown could not reach herdr: {err}"),
    }
    clear_pid_file();
}

/// Sleeps in slices so a stop request is noticed without waiting out a whole
/// scan interval.
fn nap(interval: Duration, stopping: &AtomicBool) {
    let deadline = Instant::now() + interval;
    while Instant::now() < deadline {
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(LOOP_TICK.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A panicking push must not take the badge state down with it; the data is
    // a plain map and stays consistent.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------
// Process control
// ---------------------------------------------------------------------------

/// The arguments worth handing to the detached child, normalised to the
/// `--name value` spelling. Anything else on the command line (the verb itself,
/// flags the daemon does not read) is dropped.
pub fn forwarded_args(args: &[String]) -> Result<Vec<String>> {
    let mut forwarded = Vec::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if FORWARDED_FLAGS.contains(&arg.as_str()) {
            forwarded.push(arg.clone());
            continue;
        }
        let Some(name) = FORWARDED_VALUES.into_iter().find(|name| {
            arg == name
                || arg
                    .strip_prefix(*name)
                    .is_some_and(|tail| tail.starts_with('='))
        }) else {
            continue;
        };
        let value = match arg.split_once('=') {
            Some((_, value)) => value.to_string(),
            None => rest.next().ok_or(format!("{name} needs a value"))?.clone(),
        };
        forwarded.push(name.to_string());
        forwarded.push(value);
    }
    Ok(forwarded)
}

fn spawn_detached(forwarded: &[String]) -> Result<()> {
    let exe = std::env::current_exe()?;
    let mut command = Command::new(exe);
    command
        .arg("--daemon")
        .args(forwarded)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // The child inherits our environment, and `HERDR_PANE_ID` in it names
        // the pane the *user* ran `--enable` from. The scan filter reads that
        // variable to avoid scanning its own findings pane, so a daemon that
        // kept it would skip the user's shell for its entire life — and report
        // the skip as deliberate.
        //
        // That is the worst possible pane to lose. The README's own argument is
        // that the terminal where somebody ran `cat .env` is usually a shell
        // rather than an agent pane, and a shell is exactly where `--enable`
        // gets typed.
        //
        // A daemon has no pane of its own, so unsetting is correct rather than
        // merely convenient. `--watch`, which really does run in a pane, keeps
        // the variable.
        .env_remove("HERDR_PANE_ID");
    // A daemon herdr spawned as a child dies with herdr. `setsid` puts it in
    // its own session so it survives; a double fork is not needed, and the
    // extra process would only make the pid we record harder to track.
    unsafe {
        command.pre_exec(|| {
            // EPERM here just means we are already a session leader.
            libc::setsid();
            Ok(())
        });
    }
    let child = command.spawn()?;
    write_pid(child.id());
    Ok(())
}

fn request_stop(pid: i32) {
    // SIGTERM, not SIGKILL: the daemon's handler is what clears the badges.
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
}

fn await_exit(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !is_alive(pid) {
            return true;
        }
        std::thread::sleep(STOP_POLL);
    }
    !is_alive(pid)
}

fn is_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // Signal 0 checks for existence without delivering anything. EPERM means
    // the process exists but belongs to someone else.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Guards against pid reuse. The state dir outlives reboots, so a recorded pid
/// can easily belong to something else entirely by the time we read it.
#[cfg(target_os = "linux")]
fn same_program(pid: i32) -> bool {
    let ours = fs::read_to_string("/proc/self/comm");
    let theirs = fs::read_to_string(format!("/proc/{pid}/comm"));
    match (ours, theirs) {
        (Ok(ours), Ok(theirs)) => ours.trim() == theirs.trim(),
        // /proc unreadable (hidepid, a stripped container): fall back to
        // trusting the liveness probe rather than killing a live daemon's
        // marker.
        _ => true,
    }
}

#[cfg(not(target_os = "linux"))]
fn same_program(_pid: i32) -> bool {
    // No portable equivalent of /proc/<pid>/comm; liveness is all we have.
    true
}

// ---------------------------------------------------------------------------
// Markers
// ---------------------------------------------------------------------------

/// The pid of a daemon that is live *right now*, or `None`. A stale or reused
/// pid file is swept as a side effect so the next verb starts from a clean
/// state.
pub fn live_pid() -> Option<i32> {
    let recorded = read_pid()?;
    if is_alive(recorded) && same_program(recorded) {
        return Some(recorded);
    }
    clear_pid_file();
    None
}

pub fn read_pid() -> Option<i32> {
    fs::read_to_string(config::pid_file())
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 0)
}

pub fn write_pid(pid: u32) {
    // Best effort: an unwritable state dir must not fail the user's action,
    // but it must not be silent either — without the marker, `--enable` will
    // happily start a second daemon.
    let path = config::pid_file();
    if let Err(err) = write_marker(&path, &pid.to_string()) {
        eprintln!("redact: could not record pid in {}: {err}", path.display());
    }
}

/// Removes the pid file, but only if it still names this process or a dead one,
/// so a successor daemon's marker is never deleted.
pub fn clear_pid_file() {
    match read_pid() {
        Some(pid) if pid != std::process::id() as i32 && is_alive(pid) && same_program(pid) => {}
        _ => {
            let _ = fs::remove_file(config::pid_file());
        }
    }
}

/// Did the user ever ask for a daemon? Consulted by `--restore`.
pub fn is_enabled() -> bool {
    config::enabled_flag().exists()
}

pub fn mark_enabled(enabled: bool) {
    let path = config::enabled_flag();
    let outcome = if enabled {
        write_marker(&path, "1")
    } else {
        match fs::remove_file(&path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    };
    if let Err(err) = outcome {
        eprintln!("redact: could not update {}: {err}", path.display());
    }
}

fn write_marker(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}
