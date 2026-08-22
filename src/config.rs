//! Configuration, plugin identity, and the state/config directories herdr hands
//! us. Owned by the integrator; the other modules read it, none of them change
//! it.

use std::path::PathBuf;
use std::time::Duration;

use crate::Result;

pub const PLUGIN_ID: &str = "moneycaringcoder.redact";

pub const DEFAULT_INTERVAL_SECONDS: u64 = 5;
pub const MIN_INTERVAL_SECONDS: u64 = 1;
/// Bounded so the derived TTL can never exceed herdr's 24h ceiling. The
/// compile-time assertion below keeps the two in step.
pub const MAX_INTERVAL_SECONDS: u64 = 3_600;

/// Lines of pane output read per cycle. Big enough to cover a full screen plus
/// recent scrollback on a tall terminal, small enough that scanning fifteen
/// panes every few seconds is free.
pub const DEFAULT_LINES: u32 = 400;
pub const MAX_LINES: u32 = 20_000;
/// Lines of scrollback read the first time the watcher reaches each pane.
pub const DEFAULT_BACKFILL_LINES: u32 = 5_000;

/// Cap on stored findings, so a pathological pane cannot grow the state file
/// without bound. Oldest acknowledged findings are dropped first.
pub const DEFAULT_MAX_FINDINGS: usize = 500;

const MAX_TTL_MS: u64 = 86_400_000;
/// The derived TTL is three times the interval plus the reading budget, and the
/// budget is ceilinged at 120 seconds. Keeps `ttl_ms`'s clamp from ever being
/// the thing that saves us.
const _: () = assert!((MAX_INTERVAL_SECONDS + 120).saturating_mul(3_000) <= MAX_TTL_MS);

/// One user-supplied rule from the config file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize)]
pub struct CustomPattern {
    /// Machine name used by persisted findings and suppressions, the per-run
    /// notification limiter, `--explain`, and JSON `pattern`/SARIF `ruleId` fields.
    pub name: String,
    /// Names this pattern used to have, so a stored suppression or `--explain`
    /// query using one keeps working and reports that it is out of date.
    #[serde(default)]
    pub former_names: Vec<String>,
    /// Rust `regex` syntax. Compiled by `scan::Rules::compile`, which reports a
    /// bad one rather than dropping it silently.
    pub regex: String,
    /// Human name. Defaults to `name` when absent.
    #[serde(default)]
    pub label: Option<String>,
    /// `true` (the default) reports at `Confidence::Strong`. A team that wants
    /// its internal pattern treated as a hint sets this to `false`.
    #[serde(default = "yes")]
    pub strong: bool,
}

fn yes() -> bool {
    true
}

/// One pane-context selector for a configuration overlay.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlayMatcher {
    WorkspaceId(String),
    WorkspaceLabel(String),
    PathPrefix(PathBuf),
}

impl OverlayMatcher {
    fn matches(&self, pane: &crate::model::PaneRef) -> bool {
        match self {
            Self::WorkspaceId(id) => pane.workspace_id == *id,
            Self::WorkspaceLabel(label) => pane.workspace_label == *label,
            Self::PathPrefix(prefix) => {
                pane.cwd.as_ref().is_some_and(|cwd| cwd.starts_with(prefix))
            }
        }
    }

    /// Why this matcher may not be used, if it may not be.
    ///
    /// `Path::new("/anything").starts_with("")` is true, so an empty
    /// `path_prefix` matches every pane in the session and applies its overlay
    /// everywhere — turning `notify: false` or a narrow `lines` into a
    /// session-wide setting with nothing on screen to say so. A matcher that
    /// quietly matches everything is the one failure mode this feature cannot
    /// have: the user believes an overlay is scoped, the display agrees with
    /// them, and a rule is silenced everywhere. So it is malformed and ignored
    /// with a note, never honoured as a catch-all.
    fn rejection(&self) -> Option<&'static str> {
        match self {
            Self::PathPrefix(prefix) if prefix.to_string_lossy().trim().is_empty() => {
                Some("path_prefix is empty, which would match every pane")
            }
            _ => None,
        }
    }
}

/// Optional configuration applied when [`Overlay::matcher`] matches a pane.
///
/// Overlays are considered in file order. For each scalar field, the first
/// matching overlay that names that field wins. List fields from every matching
/// overlay append in file order; path-prefix matches are not sorted by
/// specificity. This deliberately makes precedence visible and deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize)]
pub struct Overlay {
    #[serde(rename = "match")]
    pub matcher: OverlayMatcher,
    #[serde(default)]
    pub interval_seconds: Option<u64>,
    #[serde(default)]
    pub lines: Option<u32>,
    #[serde(default)]
    pub scan_all_panes: Option<bool>,
    #[serde(default)]
    pub env_assignments: Option<bool>,
    #[serde(default)]
    pub notify: Option<bool>,
    #[serde(default)]
    pub patterns: Option<Vec<CustomPattern>>,
    #[serde(default)]
    pub allowlist: Option<Vec<String>>,
    #[serde(default)]
    pub ignore_panes: Option<Vec<String>>,
    #[serde(default)]
    pub max_findings: Option<usize>,
}

impl Overlay {
    pub fn new(matcher: OverlayMatcher) -> Self {
        Self {
            matcher,
            interval_seconds: None,
            lines: None,
            scan_all_panes: None,
            env_assignments: None,
            notify: None,
            patterns: None,
            allowlist: None,
            ignore_panes: None,
            max_findings: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    pub interval: Duration,
    /// Lines of terminal output read per pane per cycle.
    pub lines: u32,
    /// Lines of terminal scrollback read the first time the watcher reaches a
    /// pane. Zero disables the startup backfill.
    pub backfill_lines: u32,
    /// Scan every pane, not just the ones herdr reports an agent for. Off by
    /// default: agent panes are the stated exposure surface, and the README
    /// says how to widen it.
    pub scan_all_panes: bool,
    /// The `.env`-style assignment heuristic (`FOO_TOKEN=…`). On, but it reports
    /// at `Confidence::Weak` and gets its own badge token.
    pub env_assignments: bool,
    /// Compiled-in rule packs to enable in addition to the always-on default
    /// pack. Unknown names are ignored with a note from the compiled rule set.
    pub rule_packs: Vec<String>,
    /// Post a herdr toast for a new finding. Rate limited to one per pattern per
    /// pane per daemon run regardless of this setting.
    pub notify: bool,
    /// Extra rules, because every team has an internal token format.
    pub patterns: Vec<CustomPattern>,
    /// Regexes that suppress a finding, because every repo has a noisy file. A
    /// finding is dropped when the allowlist matches either the matched value or
    /// the line it was found on.
    pub allowlist: Vec<String>,
    /// Pane ids never read at all. Escape hatch for a pane that is deliberately
    /// full of test credentials.
    pub ignore_panes: Vec<String>,
    pub max_findings: usize,
    pub overlays: Vec<Overlay>,
    /// Non-fatal configuration diagnostics, including ignored malformed
    /// overlays. These are carried into the effective rule set for inspection.
    pub notes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(DEFAULT_INTERVAL_SECONDS),
            lines: DEFAULT_LINES,
            backfill_lines: DEFAULT_BACKFILL_LINES,
            scan_all_panes: false,
            env_assignments: true,
            rule_packs: vec!["default".to_string()],
            notify: true,
            patterns: Vec::new(),
            allowlist: Vec::new(),
            ignore_panes: Vec::new(),
            max_findings: DEFAULT_MAX_FINDINGS,
            overlays: Vec::new(),
            notes: Vec::new(),
        }
    }
}

impl Config {
    /// How long one cycle may spend reading panes.
    ///
    /// Reading is one round trip per pane, and on a live 37-pane session some
    /// reads took 1.7 seconds each — thirty seconds for a sweep, against a
    /// five-second interval. Without a deadline the cycle simply never returns
    /// and the badge is never pushed.
    ///
    /// Two intervals, floored at half a minute so a one-second interval does not
    /// starve a large session, and ceilinged so a single wedged cycle cannot run
    /// for an hour.
    pub fn cycle_budget(&self) -> Duration {
        self.interval
            .saturating_mul(2)
            .clamp(Duration::from_secs(30), Duration::from_secs(120))
    }

    /// TTL for a badge push: three cycles' worth, so one missed cycle does not
    /// blink the badge out, clamped to herdr's ceiling.
    ///
    /// Derived from the interval **plus the reading budget**, not the interval
    /// alone. A cycle costs its reading time and then sleeps for the interval,
    /// so on a large session the gap between two pushes is dominated by the
    /// reading. Sizing the TTL off the interval alone was observed live to
    /// expire the badge between cycles: it appeared, then vanished, then
    /// appeared again — which reads as a bug in the plugin, and is one.
    ///
    /// The cost of the wider window is that a SIGKILLed daemon leaves its badge
    /// standing for up to that long. A stale badge that self-heals is a much
    /// smaller problem than a badge that flickers.
    pub fn ttl_ms(&self) -> u64 {
        self.interval
            .saturating_add(self.cycle_budget())
            .as_secs()
            .saturating_mul(3_000)
            .clamp(1, MAX_TTL_MS)
    }

    /// Returns the top-level configuration with overlay declarations removed.
    pub fn base(&self) -> Self {
        let mut base = self.clone();
        base.overlays.clear();
        base
    }

    /// Resolves this base configuration for one snapshot pane without I/O.
    ///
    /// The daemon uses the returned value as the key of its compiled-rule-set
    /// cache. That key is the whole `Config`, `overlays` included, which reads
    /// like a bug and is not: the value is built from [`Config::base`], so its
    /// `overlays` field is empty by construction and contributes nothing to
    /// equality or the hash. Two panes share a compilation exactly when every
    /// resolved setting agrees, which is the intended key.
    pub fn effective_for(&self, pane: &crate::model::PaneRef) -> Self {
        let matching: Vec<&Overlay> = self
            .overlays
            .iter()
            .filter(|overlay| overlay.matcher.matches(pane))
            .collect();
        let mut effective = self.base();

        if let Some(value) = matching.iter().find_map(|overlay| overlay.interval_seconds) {
            effective.interval =
                Duration::from_secs(value.clamp(MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS));
        }
        if let Some(value) = matching.iter().find_map(|overlay| overlay.lines) {
            effective.lines = value.clamp(1, MAX_LINES);
        }
        if let Some(value) = matching.iter().find_map(|overlay| overlay.scan_all_panes) {
            effective.scan_all_panes = value;
        }
        if let Some(value) = matching.iter().find_map(|overlay| overlay.env_assignments) {
            effective.env_assignments = value;
        }
        if let Some(value) = matching.iter().find_map(|overlay| overlay.notify) {
            effective.notify = value;
        }
        if let Some(value) = matching.iter().find_map(|overlay| overlay.max_findings) {
            effective.max_findings = value.max(1);
        }
        for overlay in matching {
            if let Some(patterns) = &overlay.patterns {
                effective.patterns.extend(patterns.iter().cloned());
            }
            if let Some(allowlist) = &overlay.allowlist {
                effective.allowlist.extend(allowlist.iter().cloned());
            }
            if let Some(ignore_panes) = &overlay.ignore_panes {
                effective.ignore_panes.extend(ignore_panes.iter().cloned());
            }
        }
        effective
    }

    /// Parses the on-disk JSON form. Invalid overlay entries are ignored and
    /// recorded in [`Config::notes`] without discarding the valid base fields.
    pub fn from_json(raw: &str) -> Result<Self> {
        let file: FileConfig = serde_json::from_str(raw)?;
        Ok(Self::from_file(file))
    }

    fn from_file(file: FileConfig) -> Self {
        let mut config = Self::default();
        if let Some(seconds) = file.interval_seconds {
            config.interval = Duration::from_secs(seconds);
        }
        if let Some(lines) = file.lines {
            config.lines = lines;
        }
        if let Some(lines) = file.backfill_lines {
            config.backfill_lines = lines;
        }
        if let Some(rule_packs) = file.rule_packs {
            config.rule_packs = rule_packs;
        }
        if let Some(all) = file.scan_all_panes {
            config.scan_all_panes = all;
        }
        if let Some(env) = file.env_assignments {
            config.env_assignments = env;
        }
        if let Some(notify) = file.notify {
            config.notify = notify;
        }
        if let Some(patterns) = file.patterns {
            config.patterns = patterns;
        }
        if let Some(allowlist) = file.allowlist {
            config.allowlist = allowlist;
        }
        if let Some(ignore) = file.ignore_panes {
            config.ignore_panes = ignore;
        }
        if let Some(max) = file.max_findings {
            config.max_findings = max.max(1);
        }
        if let Some(raw_overlays) = file.overlays {
            match raw_overlays {
                serde_json::Value::Array(overlays) => {
                    for (index, raw_overlay) in overlays.into_iter().enumerate() {
                        match serde_json::from_value::<Overlay>(raw_overlay) {
                            Ok(overlay) => match overlay.matcher.rejection() {
                                Some(reason) => config.notes.push(format!(
                                    "ignoring malformed overlay {}: {reason}",
                                    index + 1
                                )),
                                None => config.overlays.push(overlay),
                            },
                            Err(err) => config
                                .notes
                                .push(format!("ignoring malformed overlay {}: {err}", index + 1)),
                        }
                    }
                }
                _ => config
                    .notes
                    .push("ignoring malformed overlays: expected a list".to_string()),
            }
        }
        config
    }
}

pub fn load() -> Result<Config> {
    load_with_args(&[])
}

/// Loads the config file, then applies command-line overrides.
pub fn load_with_args(args: &[String]) -> Result<Config> {
    let mut config = load_file();
    if let Some(seconds) = value_arg(args, "--interval")? {
        config.interval = Duration::from_secs(
            seconds
                .trim()
                .parse::<u64>()
                .map_err(|err| format!("--interval {seconds}: {err}"))?,
        );
    }
    if let Some(lines) = value_arg(args, "--lines")? {
        config.lines = lines
            .trim()
            .parse::<u32>()
            .map_err(|err| format!("--lines {lines}: {err}"))?;
    }
    if args.iter().any(|a| a == "--all-panes") {
        config.scan_all_panes = true;
    }
    // Clamped last so neither source can push the derived TTL past herdr's
    // ceiling or below its floor.
    config.interval = Duration::from_secs(
        config
            .interval
            .as_secs()
            .clamp(MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS),
    );
    config.lines = config.lines.clamp(1, MAX_LINES);
    // Unlike the ordinary per-cycle window, zero deliberately disables the
    // startup backfill.
    if config.backfill_lines > 0 {
        config.backfill_lines = config.backfill_lines.clamp(1, MAX_LINES);
    }
    Ok(config)
}

/// The on-disk form. Every field is optional so a partial file overrides only
/// what it names, and unknown keys are ignored so a newer file does not break an
/// older binary.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct FileConfig {
    interval_seconds: Option<u64>,
    lines: Option<u32>,
    backfill_lines: Option<u32>,
    scan_all_panes: Option<bool>,
    env_assignments: Option<bool>,
    rule_packs: Option<Vec<String>>,
    notify: Option<bool>,
    patterns: Option<Vec<CustomPattern>>,
    allowlist: Option<Vec<String>>,
    ignore_panes: Option<Vec<String>>,
    max_findings: Option<usize>,
    overlays: Option<serde_json::Value>,
}

pub fn config_file() -> PathBuf {
    config_dir().join("config.json")
}

/// Reads the config file over the defaults. A missing file is the normal case;
/// an unreadable or malformed one is a warning and the defaults, never a hard
/// failure — a typo in a config file must not stop the scanner from running.
fn load_file() -> Config {
    let path = config_file();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                eprintln!("redact: ignoring {}: {err}", path.display());
            }
            return Config::default();
        }
    };
    let mut config = match Config::from_json(&raw) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("redact: ignoring malformed {}: {err}", path.display());
            return Config::default();
        }
    };
    for note in &config.notes {
        eprintln!("redact: {note}");
    }
    config.interval = Duration::from_secs(
        config
            .interval
            .as_secs()
            .clamp(MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS),
    );
    config.lines = config.lines.clamp(1, MAX_LINES);
    config
}

/// Value of `--name <VALUE>` or `--name=<VALUE>`, last occurrence winning. A
/// missing or malformed value the user typed is a hard error, unlike a malformed
/// config file: they are looking right at it and silently ignoring it would be
/// worse.
///
/// `daemon::forwarded_args` recognises the same two spellings, so an argument
/// survives being handed to the detached child.
pub fn value_arg(args: &[String], name: &str) -> Result<Option<String>> {
    let flag = format!("{name}=");
    let mut found = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if let Some(value) = arg.strip_prefix(&flag) {
            found = Some(value.to_string());
        } else if arg == name {
            found = Some(rest.next().ok_or(format!("{name} needs a value"))?.clone());
        }
    }
    Ok(found)
}

pub fn plugin_id() -> String {
    non_empty_env("HERDR_PLUGIN_ID").unwrap_or_else(|| PLUGIN_ID.to_string())
}

/// Where the daemon's markers and the findings store live:
/// `~/.local/state/herdr/plugins/<id>/`.
///
/// herdr injects `HERDR_PLUGIN_STATE_DIR` and is authoritative when it does, but
/// the fallback has to resolve to the *same* directory. A fallback that pointed
/// somewhere else would give `--enable` from a plugin action and `--disable`
/// from a shell two different state dirs: the hand-run disable finds no pid
/// file, silently does nothing, and leaves a daemon the user cannot stop.
pub fn state_dir() -> PathBuf {
    non_empty_env("HERDR_PLUGIN_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            xdg_dir("XDG_STATE_HOME", ".local/state")
                .join("herdr")
                .join("plugins")
                .join(plugin_id())
        })
}

/// Where the config file lives: `~/.config/herdr/plugins/config/<id>/`. Same
/// split-brain rule as [`state_dir`].
pub fn config_dir() -> PathBuf {
    non_empty_env("HERDR_PLUGIN_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            xdg_dir("XDG_CONFIG_HOME", ".config")
                .join("herdr")
                .join("plugins")
                .join("config")
                .join(plugin_id())
        })
}

/// An XDG base directory. The variable wins when it is set to an absolute path —
/// the spec says a relative one must be ignored — otherwise `$HOME/<relative>`.
///
/// The temp path is a last resort for a process with no home directory at all.
/// It is the wrong place for state, but it is better than the working directory,
/// which for this plugin is somebody's repository.
fn xdg_dir(variable: &str, relative: &str) -> PathBuf {
    if let Some(base) = non_empty_env(variable)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        return base;
    }
    match non_empty_env("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        Some(home) => home.join(relative),
        None => std::env::temp_dir().join("herdr-no-home"),
    }
}

/// Marker: a daemon is live right now.
pub fn pid_file() -> PathBuf {
    state_dir().join("watcher.pid")
}

/// Marker: the user asked for a daemon at some point. Survives restarts, and is
/// what `--restore` consults.
pub fn enabled_flag() -> PathBuf {
    state_dir().join("enabled")
}
/// Marker: badges and notifications are hidden until the absolute Unix
/// timestamp stored in this file. The daemon keeps scanning while it exists.
pub fn quiet_file() -> PathBuf {
    state_dir().join("quiet")
}

/// Persisted findings and acknowledgements.
pub fn findings_file() -> PathBuf {
    state_dir().join("findings.json")
}

/// The per-installation digest key. Kept in its own file so the findings file
/// can be handed to a maintainer for debugging without it.
pub fn key_file() -> PathBuf {
    state_dir().join("digest.key")
}

/// herdr injects empty strings for absent context, so empty means unset.
pub fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}
