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

/// Cap on stored findings, so a pathological pane cannot grow the state file
/// without bound. Oldest acknowledged findings are dropped first.
pub const DEFAULT_MAX_FINDINGS: usize = 500;

const MAX_TTL_MS: u64 = 86_400_000;
const _: () = assert!(MAX_INTERVAL_SECONDS.saturating_mul(3_000) <= MAX_TTL_MS);

/// One user-supplied rule from the config file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct CustomPattern {
    /// Machine name, used by the allowlist and by notification rate limiting.
    pub name: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub interval: Duration,
    /// Lines of terminal output read per pane per cycle.
    pub lines: u32,
    /// Scan every pane, not just the ones herdr reports an agent for. Off by
    /// default: agent panes are the stated exposure surface, and the README
    /// says how to widen it.
    pub scan_all_panes: bool,
    /// The `.env`-style assignment heuristic (`FOO_TOKEN=…`). On, but it reports
    /// at `Confidence::Weak` and gets its own badge token.
    pub env_assignments: bool,
    /// The entropy heuristic. **Off by default and staying that way** — it is
    /// the false-positive machine this plugin exists to avoid being.
    pub entropy: bool,
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(DEFAULT_INTERVAL_SECONDS),
            lines: DEFAULT_LINES,
            scan_all_panes: false,
            env_assignments: true,
            entropy: false,
            notify: true,
            patterns: Vec::new(),
            allowlist: Vec::new(),
            ignore_panes: Vec::new(),
            max_findings: DEFAULT_MAX_FINDINGS,
        }
    }
}

impl Config {
    /// TTL for a badge push: three refresh cycles, so one missed cycle does not
    /// blink the badge out, clamped to herdr's ceiling.
    pub fn ttl_ms(&self) -> u64 {
        self.interval
            .as_secs()
            .saturating_mul(3_000)
            .clamp(1, MAX_TTL_MS)
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
    scan_all_panes: Option<bool>,
    env_assignments: Option<bool>,
    entropy: Option<bool>,
    notify: Option<bool>,
    patterns: Option<Vec<CustomPattern>>,
    allowlist: Option<Vec<String>>,
    ignore_panes: Option<Vec<String>>,
    max_findings: Option<usize>,
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
    let file: FileConfig = match serde_json::from_str(&raw) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("redact: ignoring malformed {}: {err}", path.display());
            return Config::default();
        }
    };

    let mut config = Config::default();
    if let Some(seconds) = file.interval_seconds {
        config.interval = Duration::from_secs(seconds);
    }
    if let Some(lines) = file.lines {
        config.lines = lines;
    }
    if let Some(all) = file.scan_all_panes {
        config.scan_all_panes = all;
    }
    if let Some(env) = file.env_assignments {
        config.env_assignments = env;
    }
    if let Some(entropy) = file.entropy {
        config.entropy = entropy;
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
