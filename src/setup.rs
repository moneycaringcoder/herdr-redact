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
///
/// The scan is character-level rather than line-level because both shapes occur
/// in real configs: `rows` spread over many lines with one row per line, and the
/// whole array on a single line. A line-oriented version of this got the second
/// case wrong by splicing at the last `]` on the line, which is the one closing
/// the *rows array* rather than the last row — valid TOML that herdr accepts and
/// then renders nothing from.
fn splice_section(text: &str, section: &str) -> Option<String> {
    let Some(section_start) = find_section(text, section) else {
        // Only the spaces sidebar is worth inventing from nothing. A user with
        // no `[ui.sidebar.agents]` section is on herdr's default agent rows, and
        // replacing those wholesale would be a much bigger change than they
        // asked for.
        return (section == SECTIONS[0]).then(|| append_section(text, section));
    };
    let section_end = next_section(text, section_start);
    let region = &text[section_start..section_end];

    let rows_open = find_rows_array(region)? + section_start;
    let (row_open, row_close) = last_row_span(text, rows_open)?;

    // Insert after the row's last piece of content rather than immediately
    // before its `]`. Whatever whitespace separated the two — nothing at all, or
    // a newline and the closing bracket's own indentation — is then preserved
    // exactly, which is what keeps the result looking hand-written in both
    // layouts herdr's own examples use.
    let content_end = text[..row_close]
        .trim_end_matches([' ', '\t', '\n', '\r'])
        .len();
    let head = &text[row_open..content_end];
    // An empty row needs no separator; anything else needs the comma the user's
    // last entry does not have, because their `]` followed it directly.
    let separator = if head.ends_with('[') { "" } else { "," };

    let entries: Vec<String> = token_lines()
        .into_iter()
        .map(|line| line.trim().trim_end_matches(',').to_string())
        .collect();

    // A row written across several lines gets the entries as their own lines,
    // matching the surrounding style; a row on one line gets them inline.
    let mut insert = String::from(separator);
    if head.contains('\n') {
        let indent = line_indent(text, content_end);
        for (n, entry) in entries.iter().enumerate() {
            insert.push('\n');
            insert.push_str(&indent);
            insert.push_str(entry);
            if n + 1 < entries.len() {
                insert.push(',');
            }
        }
    } else {
        insert.push(' ');
        insert.push_str(&entries.join(", "));
    }

    let mut out = String::with_capacity(text.len() + insert.len());
    out.push_str(&text[..content_end]);
    out.push_str(&insert);
    out.push_str(&text[content_end..]);
    Some(out)
}

/// Byte offset of a top-level table header, matched at the start of a line.
fn find_section(text: &str, section: &str) -> Option<usize> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if line.trim_start().starts_with(section) {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

/// Byte offset where the next top-level table starts, or the end of the file.
/// A row line such as `["$context"],` also begins with `[`, so a header is only
/// recognised when the bracket is followed by a bare key.
fn next_section(text: &str, from: usize) -> usize {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let here = offset;
        offset += line.len();
        if here <= from {
            continue;
        }
        let trimmed = line.trim_start();
        let after = trimmed.trim_start_matches('[');
        if trimmed.starts_with('[')
            && after
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            return here;
        }
    }
    text.len()
}

/// Byte offset, within `region`, of the `[` that opens this section's `rows`
/// array.
fn find_rows_array(region: &str) -> Option<usize> {
    let mut offset = 0usize;
    for line in region.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("rows") && line.contains('[') {
            return line.find('[').map(|column| offset + column);
        }
        offset += line.len();
    }
    None
}

/// Byte offsets of the opening `[` and the closing `]` of the **last** row in
/// the array opened at `rows_open`.
///
/// Quoted strings are skipped, so a token value containing a bracket cannot move
/// the insert point.
fn last_row_span(text: &str, rows_open: usize) -> Option<(usize, usize)> {
    let mut depth = 1usize; // inside the rows array
    let mut in_string = false;
    let mut row_open: Option<usize> = None;
    let mut span: Option<(usize, usize)> = None;

    for (offset, ch) in text[rows_open + 1..].char_indices() {
        let at = rows_open + 1 + offset;
        if in_string {
            if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '[' => {
                depth += 1;
                if depth == 2 {
                    row_open = Some(at);
                }
            }
            ']' => {
                if depth == 2 {
                    if let Some(open) = row_open.take() {
                        span = Some((open, at));
                    }
                }
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    span
}

/// The leading whitespace of the line containing `offset`, so an inserted block
/// leaves the closing bracket where it was.
fn line_indent(text: &str, offset: usize) -> String {
    let start = text[..offset].rfind('\n').map_or(0, |n| n + 1);
    text[start..offset]
        .chars()
        .take_while(|c| c.is_whitespace() && *c != '\n')
        .collect()
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
