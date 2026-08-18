//! redact — credential warnings for herdr agent panes.
//!
//! Verb dispatch only; every verb is implemented in the library crate.

use redact::{config, daemon, findings::Store, render, setup, Result};

const USAGE: &str = "\
redact — credential warnings for herdr agent panes

Usage: redact [VERB]

Scanning:
  --once              Scan every agent pane once, print the findings, exit
  --calibrate         Report what the active rules would fire on, without badging
  --json              Print the same findings as JSON and exit
  --sarif             Print the same findings as SARIF 2.1.0 and exit
  --watch             Live findings pane (a acknowledges, s permanently suppresses)
  --rules             List the active detection rules and exit
  --explain <RULE>    Explain one active detection rule and exit

Findings:
  --ack <ID>          Acknowledge one finding by id or id prefix
  --suppress <ID>     Acknowledge and permanently suppress its exact value
  --suppressions      List active suppressions (rule and short digest only)
  --ack-all           Acknowledge every current finding
  --forget            Clear findings and permanent suppressions

Watcher:
  --enable            Start the background pane watcher
  --disable           Stop it and clear every badge this plugin set
  --toggle            Stop it if running, otherwise start it
  --restore           Restart it only if it was enabled (herdr startup hook)
  --daemon            Run the watcher in the foreground (internal)
  --status            Report whether the watcher is running
  --quiet <DURATION>  Hide badges and toasts for minutes, `10m`, or `1h` (max 4h)
  --loud              End quiet mode early


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
/// `--ack`, `--explain` and `--suppress` are deliberately absent: each takes a
/// value *and* is the verb, so it has to be returned rather than skipped over.
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
        return arg;
    }
    "--once"
}

fn run(args: &[String]) -> Result<()> {
    let verb = verb_of(args);
    match verb {
        "--once" => render::run_once(&config::load_with_args(args)?),
        "--calibrate" => render::run_calibrate(&config::load_with_args(args)?),
        "--json" => render::run_json(&config::load_with_args(args)?),
        "--sarif" => render::run_sarif(&config::load_with_args(args)?),
        "--watch" => render::run_watch(&config::load_with_args(args)?),
        "--rules" => rules(&config::load_with_args(args)?),
        "--explain" => explain(args),
        "--ack" => acknowledge(args),
        "--suppress" => suppress(args),
        "--suppressions" => suppressions(),
        "--ack-all" => acknowledge_all(),
        "--forget" => forget(),
        "--enable" => daemon::enable(args),
        "--disable" => daemon::disable(),
        "--quiet" => quiet(args),
        "--loud" => loud(),
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
fn rules(config: &config::Config) -> Result<()> {
    let rules = redact::scan::Rules::compile(config)?;
    if rules.names.is_empty() {
        println!("redact: no rules are active.");
        return Ok(());
    }
    for ((name, confidence), pack) in rules.names.iter().zip(&rules.packs) {
        match pack {
            Some(pack) => println!(
                "{name}\t{}\t{}\t{}",
                confidence.as_str(),
                pack.name,
                pack.version
            ),
            None => println!("{name}\t{}\t-\t-", confidence.as_str()),
        }
    }
    // A note here usually means a setting the user believes is doing something
    // and is not. Printing it on the rule listing is where they will look.
    for note in &rules.notes {
        eprintln!("redact: {note}");
    }
    Ok(())
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

fn suppress(args: &[String]) -> Result<()> {
    let id = config::value_arg(args, "--suppress")?.ok_or("--suppress needs a finding id")?;
    let config = config::load()?;
    let mut store = Store::load(&config);
    let count = store.suppress(id.trim());
    if count == 0 {
        return Err(format!("no finding matches `{id}`").into());
    }
    store.save()?;
    println!(
        "redact: suppressed {count} finding(s) permanently; each exact value will be ignored \
         globally across panes for that rule."
    );
    Ok(())
}

fn suppressions() -> Result<()> {
    let config = config::load()?;
    let store = Store::load(&config);
    if store.suppressions().is_empty() {
        println!("redact: no permanent suppressions are active.");
        return Ok(());
    }
    for suppression in store.suppressions() {
        println!("{}\t{}", suppression.rule(), suppression.short_digest());
    }
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
    let suppressions = store.suppression_count();
    let findings = store.forget_all();
    store.save()?;
    println!(
        "redact: forgot {findings} finding(s) and cleared {suppressions} permanent suppression(s)."
    );
    Ok(())
}

fn quiet(args: &[String]) -> Result<()> {
    let duration = config::value_arg(args, "--quiet")?.ok_or("--quiet needs a duration")?;
    let started = daemon::start_quiet(&duration)?;
    let suffix = if started.clamped {
        " (clamped to the four-hour maximum)"
    } else {
        ""
    };
    println!(
        "redact: quiet until Unix time {}{}; scanning and finding collection continue.",
        started.until, suffix
    );
    Ok(())
}

fn loud() -> Result<()> {
    daemon::end_quiet()?;
    println!("redact: loud; badges and notifications resume on the next watcher cycle.");
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
    if let Some(until) = daemon::quiet_until() {
        println!(
            "redact: quiet for another {}, until Unix time {}; findings are still being collected.",
            daemon::quiet_remaining(until, redact::model::now()),
            until
        );
    } else {
        println!("redact: loud.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::verb_of;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_verb_is_found_whatever_the_order() {
        assert_eq!(verb_of(&args(&["--once"])), "--once");
        assert_eq!(verb_of(&args(&["--calibrate"])), "--calibrate");
        assert_eq!(verb_of(&args(&["--json", "--interval", "5"])), "--json");
        assert_eq!(verb_of(&args(&["--interval", "5", "--json"])), "--json");
        assert_eq!(verb_of(&args(&["--interval=5", "--json"])), "--json");
        assert_eq!(verb_of(&args(&["--lines", "800", "--sarif"])), "--sarif");
        assert_eq!(verb_of(&args(&["--lines", "800", "--watch"])), "--watch");
        assert_eq!(verb_of(&args(&["--all-panes", "--watch"])), "--watch");
        assert_eq!(verb_of(&args(&["--quiet", "10m"])), "--quiet");
        assert_eq!(verb_of(&args(&["--loud"])), "--loud");
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
        assert_eq!(verb_of(&args(&["--suppress", "a1b2c3"])), "--suppress");
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
}
