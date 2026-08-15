//! One-click sidebar setup.
//!
//! herdr renders a plugin's custom tokens only if the user's `config.toml` names
//! them, so without this the badge silently never appears. Rather than asking
//! people to hand-merge TOML, `--setup` splices the two token entries into their
//! existing sidebar rows, reloads herdr's config, and restores the backup
//! automatically if that reload fails.
//!
//! Safety rules this module holds to, because it edits a file it does not own:
//!
//!   * every run takes a non-clobbering backup first;
//!   * the edit is line-oriented and additive — nothing is ever deleted;
//!   * a failed reload restores the backup byte for byte;
//!   * running it twice is a no-op rather than a duplicate insert.

use std::path::{Path, PathBuf};

use crate::config::non_empty_env;
use crate::model::Alert;
use crate::Result;

/// The two sidebars this plugin badges. Findings are per-pane, so the agent row
/// is where the warning belongs; the space row carries it too, because an agent
/// panel can be collapsed and a badge nobody can see protects nobody.
const SECTIONS: [&str; 2] = ["[ui.sidebar.spaces]", "[ui.sidebar.agents]"];

const BACKUP_SUFFIX: &str = ".redact-backup";

/// Rows written into the user's config: amber for a weak hit, red for a
/// confirmed provider credential. Colours chosen to read on both light and dark
/// themes, and matched to the palette collide uses so a sidebar with both
/// plugins installed stays coherent.
///
/// `redact_clear` is deliberately absent. A target with nothing to report clears
/// its token rather than writing an empty one, so that name is never set and a
/// row naming it could never display anything. The disable sweep still clears
/// all three names defensively, which costs nothing and cannot go stale.
const TOKEN_COLOURS: [(&str, &str); 2] = [("redact_weak", "#FFC799"), ("redact_secret", "#FF8080")];

pub fn config_path() -> PathBuf {
    if let Some(explicit) = non_empty_env("HERDR_CONFIG_PATH") {
        return PathBuf::from(explicit);
    }
    herdr_dir().join("config.toml")
}

fn herdr_dir() -> PathBuf {
    if let Some(xdg) = non_empty_env("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("herdr");
    }
    match non_empty_env("HOME") {
        Some(home) => PathBuf::from(home).join(".config").join("herdr"),
        None => PathBuf::from(".config/herdr"),
    }
}

fn backup_path(config: &Path) -> PathBuf {
    let mut name = config.as_os_str().to_os_string();
    name.push(BACKUP_SUFFIX);
    PathBuf::from(name)
}

/// The rows this plugin contributes, rendered as TOML lines at the indentation
/// herdr's own examples use.
fn token_lines() -> Vec<String> {
    TOKEN_COLOURS
        .iter()
        .map(|(token, colour)| format!("    {{ token = \"${token}\", fg = \"{colour}\" }},"))
        .collect()
}

fn already_configured(text: &str) -> bool {
    Alert::ALL_TOKENS
        .iter()
        .any(|token| text.contains(&format!("\"${token}\"")))
}

/// Splices the token entries into every sidebar section this plugin badges.
///
/// Returns `None` when the file already mentions our tokens, so a second run is
/// a no-op rather than a duplicate insert.
pub fn plan_edit(text: &str) -> Option<String> {
    if already_configured(text) {
        return None;
    }
    let mut out = text.to_string();
    let mut changed = false;
    for section in SECTIONS {
        if let Some(updated) = splice_section(&out, section) {
            out = updated;
            changed = true;
        }
    }
    changed.then_some(out)
}

/// Splices the entries into one section's rows array, or appends a complete
/// section when the user has none. `None` means nothing was changed.
fn splice_section(text: &str, section: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let section_start = lines
        .iter()
        .position(|line| line.trim_start().starts_with(section));

    let Some(section_start) = section_start else {
        // Only the spaces sidebar is worth inventing from nothing. A user with
        // no `[ui.sidebar.agents]` section is using herdr's default agent rows,
        // and replacing those wholesale would be a much bigger change than they
        // asked for.
        return (section == SECTIONS[0]).then(|| append_section(text, section));
    };

    // Find the LAST row inside this section's rows array, and its final line.
    //
    // The entries have to land inside a row, not beside one. `rows` is an array
    // of arrays, and each inner array is one rendered line; a bare table dropped
    // between two rows is still valid TOML, so herdr accepts the file and then
    // renders nothing at all. That failure is invisible — which is exactly how
    // it shipped past a passing test suite once already, in collide.
    //
    // Depth 1 is inside `rows`, depth 2 is inside a row.
    let mut depth = 0usize;
    let mut in_rows = false;
    let mut row_span: Option<(usize, usize)> = None;
    let mut row_start: Option<usize> = None;

    for (offset, line) in lines.iter().enumerate().skip(section_start + 1) {
        let trimmed = line.trim_start();
        if !in_rows {
            if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
                break; // next table; this section has no rows array
            }
            if trimmed.starts_with("rows") && trimmed.contains('[') {
                in_rows = true;
                depth = line.matches('[').count() - line.matches(']').count();
                continue;
            }
            continue;
        }

        for ch in line.chars() {
            match ch {
                '[' => {
                    depth += 1;
                    if depth == 2 && row_start.is_none() {
                        row_start = Some(offset);
                    }
                }
                ']' => {
                    depth = depth.saturating_sub(1);
                    if depth == 1 {
                        if let Some(start) = row_start.take() {
                            row_span = Some((start, offset));
                        }
                    }
                }
                _ => {}
            }
        }
        if depth == 0 {
            break; // rows array closed
        }
    }

    let (row_start, row_end) = row_span?;
    let mut out: Vec<String> = lines.iter().map(|l| l.to_string()).collect();

    if row_start == row_end {
        // A single-line row: splice the entries in before its closing bracket.
        let line = out[row_end].clone();
        let close = line.rfind(']')?;
        let (head, tail) = line.split_at(close);
        let head = head.trim_end();
        let separator = if head.ends_with('[') { "" } else { "," };
        let entries: Vec<String> = token_lines()
            .into_iter()
            .map(|l| l.trim().trim_end_matches(',').to_string())
            .collect();
        out[row_end] = format!("{head}{separator} {}{tail}", entries.join(", "));
    } else {
        // A multi-line row: insert before its final line, which carries the
        // closing bracket. The preceding line already ends in a comma.
        for (n, line) in token_lines().into_iter().enumerate() {
            out.insert(row_end + n, line);
        }
    }
    Some(finish(out, text))
}

fn append_section(text: &str, section: &str) -> String {
    let mut out = text.trim_end().to_string();
    if !out.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(section);
    out.push_str("\nrows = [\n  [\"state_icon\", \"workspace\"],\n  [\"branch\",\n");
    for line in token_lines() {
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str("  ],\n]\n");
    out
}

fn finish(lines: Vec<String>, original: &str) -> String {
    let mut out = lines.join("\n");
    if original.ends_with('\n') {
        out.push('\n');
    }
    out
}

pub fn run_setup() -> Result<()> {
    let config = config_path();
    let text = std::fs::read_to_string(&config)
        .map_err(|e| format!("cannot read {}: {e}", config.display()))?;

    let Some(updated) = plan_edit(&text) else {
        println!("redact: sidebar tokens are already configured; nothing to do.");
        return Ok(());
    };

    let backup = backup_path(&config);
    if backup.exists() {
        return Err(format!(
            "refusing to overwrite an existing backup at {}; move it aside first",
            backup.display()
        )
        .into());
    }
    std::fs::write(&backup, &text)?;
    std::fs::write(&config, &updated)?;

    match reload_herdr_config() {
        Ok(()) => {
            println!(
                "redact: added sidebar tokens to {} (backup at {}).",
                config.display(),
                backup.display()
            );
            println!("redact: run `redact --setup-rollback` to undo.");
            Ok(())
        }
        Err(err) => {
            // The edit is the only thing that changed, so restoring it is a
            // complete undo. Report the original failure, not the restore.
            std::fs::write(&config, &text)?;
            let _ = std::fs::remove_file(&backup);
            Err(
                format!("herdr rejected the updated config, so it was restored unchanged: {err}")
                    .into(),
            )
        }
    }
}

pub fn run_rollback() -> Result<()> {
    let config = config_path();
    let backup = backup_path(&config);
    if !backup.exists() {
        return Err(format!("no backup found at {}", backup.display()).into());
    }
    let text = std::fs::read_to_string(&backup)?;
    std::fs::write(&config, text)?;
    std::fs::remove_file(&backup)?;
    let _ = reload_herdr_config();
    println!("redact: restored {} from backup.", config.display());
    Ok(())
}

/// Sidebar rows reload live, so the user never has to restart herdr.
fn reload_herdr_config() -> Result<()> {
    let bin = non_empty_env("HERDR_BIN_PATH").unwrap_or_else(|| "herdr".to_string());
    let output = std::process::Command::new(bin)
        .args(["server", "reload-config"])
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&output.stderr)
        .trim()
        .to_string()
        .into())
}
