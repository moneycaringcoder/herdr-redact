//! redact — credential warnings for herdr agent panes.
//!
//! Verb dispatch only; every verb is implemented in the library crate.

use redact::{config, daemon, findings::Store, render, setup, Result};

const USAGE: &str = "\
redact — credential warnings for herdr agent panes

Usage: redact [VERB]

Scanning:
  --once              Scan every agent pane once, print the findings, exit
  --json              Print the same findings as JSON and exit
  --watch             Live findings pane (a acknowledges, A acknowledges all)
  --rules             List the active detection rules and exit

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
/// `--ack` is deliberately absent: it takes a value *and* is the verb, so it has
/// to be returned rather than skipped over.
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
        "--rules" => rules(&config::load_with_args(args)?),
        "--ack" => acknowledge(args),
        "--ack-all" => acknowledge_all(),
        "--forget" => forget(),
        "--enable" => daemon::enable(args),
        "--disable" => daemon::disable(),
        "--toggle" => daemon::toggle(args),
        "--restore" => daemon::restore(),
        "--daemon" => daemon::run(&config::load_with_args(args)?),
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
    for (name, confidence) in &rules.names {
        println!("{name}\t{}", confidence.as_str());
    }
    Ok(())
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
    use super::verb_of;

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
}
