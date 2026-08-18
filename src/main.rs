//! redact — credential warnings for herdr agent panes.
//!
//! Verb dispatch only; every verb is implemented in the library crate.

use std::path::{Path, PathBuf};

use redact::{
    config, daemon, findings::Store, herdr::Herdr, model::PaneRef, render, setup, Result,
};

const USAGE: &str = "\
redact — credential warnings for herdr agent panes

Usage: redact [VERB]

Scanning:
  --once              Scan every agent pane once, print the findings, exit
  --json              Print the same findings as JSON and exit
  --watch             Live findings pane (a acknowledges, A acknowledges all)
  --rules [PANE|PATH] List active rules for the base, pane, or working directory
                      A context containing `:` is read as a pane id; anything
                      else is read as a working-directory path. Which one was
                      used is reported, so a mistyped pane id is visible
  --explain <RULE>    Explain one active detection rule and exit

Findings:
  --ack <ID>          Acknowledge one finding by id or id prefix
  --ack-all           Acknowledge every current finding
  --forget            Clear the findings store entirely

Watcher:
  --enable            Start the background pane watcher
  --disable           Stop it and clear every badge this plugin set
  --toggle            Stop it if running, otherwise start it
  --restore           Restart it only if it was enabled (herdr startup hook)
  --daemon            Run the watcher in the foreground (internal)
  --status            Report whether the watcher is running

Sidebar setup:
  --setup             Add redact's tokens to herdr's config.toml and reload
  --setup-rollback    Restore the config.toml backup taken by --setup

Other:
  --interval <SECS>   Scan interval for --watch and --daemon (default: 5)
  --lines <N>         Lines of pane output read per scan (default: 400)
  --all-panes         Scan every pane, not only panes running an agent
  --version           Print version and exit
  --help              Show this help

redact reads the terminal output of your panes. It never writes a secret
anywhere: findings record the rule name, the pane, and a masked preview.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(err) = run(&args) {
        eprintln!("redact: {err}");
        std::process::exit(1);
    }
}

/// Options that take a value, and so must never be mistaken for the verb.
///
/// `--ack` and `--explain` are deliberately absent: each takes a value *and* is
/// the verb, so it has to be returned rather than skipped over.
const VALUED: [&str; 2] = ["--interval", "--lines"];

/// The verb is the first argument that is not an option or an option's value, so
/// `redact --lines 800 --once` works as readily as `redact --once --lines 800`.
/// Ordering that matters is a papercut nobody should have to learn.
fn verb_of(args: &[String]) -> &str {
    let mut skip_value = false;
    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        let name = arg.split('=').next().unwrap_or(arg);
        if VALUED.contains(&name) {
            // `--lines=800` carries its value; bare `--lines 800` does not.
            skip_value = !arg.contains('=');
            continue;
        }
        if arg == "--all-panes" {
            continue;
        }
        // `--explain=jwt` is one argument carrying its own value. The verb is
        // still `--explain`; `value_arg` reads the half after the `=`. Only the
        // new verb does this. `--ack` has taken the space-separated form alone
        // since 0.1.0, and quietly changing an existing verb's parsing is not
        // this change's business.
        if arg.starts_with("--explain=") {
            return "--explain";
        }
        if arg.starts_with("--rules=") {
            return "--rules";
        }
        return arg;
    }
    "--once"
}

fn run(args: &[String]) -> Result<()> {
    let verb = verb_of(args);
    match verb {
        "--once" => render::run_once(&config::load_with_args(args)?),
        "--json" => render::run_json(&config::load_with_args(args)?),
        "--watch" => render::run_watch(&config::load_with_args(args)?),
        "--rules" => rules(args, &config::load_with_args(args)?),
        "--explain" => explain(args),
        "--ack" => acknowledge(args),
        "--ack-all" => acknowledge_all(),
        "--forget" => forget(),
        "--enable" => daemon::enable(args),
        "--disable" => daemon::disable(),
        "--toggle" => daemon::toggle(args),
        "--restore" => daemon::restore(),
        "--daemon" => daemon::run(args),
        "--status" => status(),
        "--setup" => setup::run_setup(),
        "--setup-rollback" => setup::run_rollback(),
        "--version" => {
            println!("redact {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "--help" | "-h" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown verb `{other}`\n\n{USAGE}").into()),
    }
}

/// The active rule set, so a user can see what is really protecting them rather
/// than what the README says is.
fn rules(args: &[String], config: &config::Config) -> Result<()> {
    let context = optional_rules_context(args)?;
    // Say which reading was used. `--rules myword` is a path lookup that
    // matches nothing, and without this line it is indistinguishable from a
    // pane id whose overlays happen to add nothing.
    if let Some(value) = context.as_deref() {
        eprintln!("redact: {}", context_interpretation(value));
    }
    let effective = match context.as_deref() {
        None => config.base(),
        Some(value) if is_path_context(value) => {
            let pane = path_context(value);
            config.effective_for(&pane)
        }
        Some(pane_id) => {
            let mut client = Herdr::connect()?;
            let panes = client.panes()?;
            let pane = panes
                .iter()
                .find(|pane| pane.pane_id == pane_id)
                .ok_or_else(|| format!("no current pane has id `{pane_id}`"))?;
            config.effective_for(pane)
        }
    };
    let rules = redact::scan::Rules::compile(&effective)?;
    if rules.names.is_empty() {
        println!("redact: no rules are active.");
        return Ok(());
    }
    for (name, confidence) in &rules.names {
        println!("{name}\t{}", confidence.as_str());
    }
    // A note here usually means a setting the user believes is doing something
    // and is not. Printing it on the rule listing is where they will look.
    for note in &rules.notes {
        eprintln!("redact: {note}");
    }
    Ok(())
}

fn optional_rules_context(args: &[String]) -> Result<Option<String>> {
    for (index, arg) in args.iter().enumerate() {
        if let Some(value) = arg.strip_prefix("--rules=") {
            if value.is_empty() {
                return Err("--rules context cannot be empty".into());
            }
            return Ok(Some(value.to_string()));
        }
        if arg == "--rules" {
            return Ok(args
                .get(index + 1)
                .filter(|value| !value.starts_with('-'))
                .cloned());
        }
    }
    Ok(None)
}

fn is_path_context(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute() || value.starts_with('.') || value.contains('/') || !value.contains(':')
}

/// How the `--rules` context was read, in the user's own words back at them.
///
/// The heuristic is unavoidably a guess, and it guesses "path" for anything
/// without a colon: `redact --rules myword` becomes a relative-path lookup that
/// matches no overlay at all. Reporting the reading is what turns that from a
/// silent empty result into an obvious typo.
fn context_interpretation(value: &str) -> String {
    if is_path_context(value) {
        format!("reading `{value}` as a working-directory path; a pane id contains a `:`")
    } else {
        format!("reading `{value}` as a pane id")
    }
}

fn path_context(value: &str) -> PaneRef {
    PaneRef {
        pane_id: String::new(),
        workspace_id: String::new(),
        tab_id: String::new(),
        workspace_label: String::new(),
        agent: None,
        title: None,
        cwd: Some(PathBuf::from(value)),
    }
}

fn explain(args: &[String]) -> Result<()> {
    let name = config::value_arg(args, "--explain")?.ok_or("--explain needs a rule name")?;
    let name = name.trim();
    let rules = redact::scan::Rules::compile(&config::load()?)?;

    if let Some(explanation) = rules.explanation(name) {
        println!("Rule: {}", explanation.name);
        println!("Label: {}", explanation.label);
        println!("Confidence: {}", explanation.confidence.as_str());
        println!();
        for line in wrap(&explanation.text, 80) {
            println!("{line}");
        }
        return Ok(());
    }

    let suggestions: Vec<&str> = rules
        .names
        .iter()
        .map(|(rule_name, _)| rule_name.as_str())
        .filter(|rule_name| rule_name.starts_with(name) || rule_name.contains(name))
        .collect();
    let mut message = format!("unknown rule `{name}`");
    if suggestions.is_empty() {
        message.push_str(
            "\nno active rule names contain that query; run `redact --rules` to list them",
        );
    } else {
        message.push_str("\npossible matches:");
        for suggestion in suggestions {
            message.push_str("\n  ");
            message.push_str(suggestion);
        }
    }
    Err(message.into())
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            lines.push(line);
            line = String::new();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn acknowledge(args: &[String]) -> Result<()> {
    let id = config::value_arg(args, "--ack")?.ok_or("--ack needs a finding id")?;
    let config = config::load()?;
    let mut store = Store::load(&config);
    let count = store.acknowledge(id.trim());
    if count == 0 {
        return Err(format!("no finding matches `{id}`").into());
    }
    store.save()?;
    println!("redact: acknowledged {count} finding(s).");
    Ok(())
}

fn acknowledge_all() -> Result<()> {
    let config = config::load()?;
    let mut store = Store::load(&config);
    let count = store.acknowledge_all();
    store.save()?;
    println!("redact: acknowledged {count} finding(s).");
    Ok(())
}

fn forget() -> Result<()> {
    let config = config::load()?;
    let mut store = Store::load(&config);
    let count = store.forget_all();
    store.save()?;
    println!("redact: forgot {count} finding(s).");
    Ok(())
}

fn status() -> Result<()> {
    match daemon::live_pid() {
        Some(pid) => println!("redact: watcher running (pid {pid})."),
        None if daemon::is_enabled() => {
            println!("redact: watcher enabled but not running; `redact --restore` will start it.")
        }
        None => println!("redact: watcher not running."),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{context_interpretation, is_path_context, optional_rules_context, verb_of};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_verb_is_found_whatever_the_order() {
        assert_eq!(verb_of(&args(&["--once"])), "--once");
        assert_eq!(verb_of(&args(&["--json", "--interval", "5"])), "--json");
        assert_eq!(verb_of(&args(&["--interval", "5", "--json"])), "--json");
        assert_eq!(verb_of(&args(&["--interval=5", "--json"])), "--json");
        assert_eq!(verb_of(&args(&["--lines", "800", "--watch"])), "--watch");
        assert_eq!(verb_of(&args(&["--all-panes", "--watch"])), "--watch");
        assert_eq!(verb_of(&args(&["--rules=/work/company"])), "--rules");
        assert_eq!(verb_of(&args(&["--rules", "/work/company"])), "--rules");
    }

    #[test]
    fn no_arguments_means_a_one_shot_report() {
        assert_eq!(verb_of(&args(&[])), "--once");
        assert_eq!(verb_of(&args(&["--interval", "5"])), "--once");
        assert_eq!(verb_of(&args(&["--all-panes"])), "--once");
    }

    #[test]
    fn an_option_value_is_never_mistaken_for_a_verb() {
        // A value that looks like a verb must still be treated as a value.
        assert_eq!(verb_of(&args(&["--lines", "--json"])), "--once");
    }

    #[test]
    fn ack_takes_a_value_and_is_still_the_verb() {
        // `--ack` is both: it names the action and carries an id. If it were
        // treated as a plain valued option the verb would silently become
        // `--once` and the acknowledgement would never happen.
        assert_eq!(verb_of(&args(&["--ack", "a1b2c3"])), "--ack");
        assert_eq!(verb_of(&args(&["--lines", "800", "--ack", "a1"])), "--ack");
    }

    #[test]
    fn explain_takes_a_value_and_is_still_the_verb() {
        assert_eq!(verb_of(&args(&["--explain", "jwt"])), "--explain");
        assert_eq!(
            verb_of(&args(&["--lines", "800", "--explain", "jwt"])),
            "--explain"
        );
        // Both spellings reach the verb. Without the `=` arm this one resolves
        // to the whole argument and the user is told `--explain=jwt` is an
        // unknown verb, which is a papercut with an obvious cause and no
        // obvious fix from the outside.
        assert_eq!(verb_of(&args(&["--explain=jwt"])), "--explain");
        assert_eq!(
            verb_of(&args(&["--explain=jwt", "--lines", "800"])),
            "--explain"
        );
    }

    #[test]
    fn rules_context_is_optional_and_supports_both_spellings() {
        assert_eq!(
            optional_rules_context(&args(&["--rules"]))
                .expect("context")
                .as_deref(),
            None
        );
        assert_eq!(
            optional_rules_context(&args(&["--rules", "w1:p2"]))
                .expect("context")
                .as_deref(),
            Some("w1:p2")
        );
        assert_eq!(
            optional_rules_context(&args(&["--rules=/work/company"]))
                .expect("context")
                .as_deref(),
            Some("/work/company")
        );
        assert!(is_path_context("/work/company"));
        assert!(is_path_context("relative/repo"));
        assert!(!is_path_context("w1:p2"));
    }

    #[test]
    fn the_reading_of_a_rules_context_is_reported() {
        // `myword` is not a pane id to this heuristic, and a user who meant one
        // has no other way to find that out: the listing looks identical.
        assert_eq!(
            context_interpretation("myword"),
            "reading `myword` as a working-directory path; a pane id contains a `:`"
        );
        assert_eq!(
            context_interpretation("/work/company"),
            "reading `/work/company` as a working-directory path; a pane id contains a `:`"
        );
        assert_eq!(
            context_interpretation("w1:p2"),
            "reading `w1:p2` as a pane id"
        );
    }
}
