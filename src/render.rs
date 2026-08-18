//! Rendering: the badge string that rides a token, the findings pane, and the
//! machine-readable snapshot.
//!
//! # Contract
//!
//! * Nothing here emits colour. herdr renders a token value as flat text and
//!   cannot colour by content, so severity travels in the token *name*
//!   (`Alert::token_name`).
//! * [`badge`] is the single author of badge text, and renders a clear target as
//!   the empty string, which the daemon treats as "clear the token" rather than
//!   "write an empty one".
//! * The formatting half of the module is pure, and is what `tests/render.rs`
//!   exercises. Only `run_watch` talks to herdr.
//! * No renderer may print a value. It only ever has a masked preview to print,
//!   which is the point.
//!
//! # Widths
//!
//! Every width in this file is a *display column* count, never a byte or `char`
//! count. The marks below are multi-byte, a pane label can be CJK or emoji, and
//! a badge measured in `char`s is a badge that silently pushes its neighbour off
//! the sidebar row.
//!
//! # "Nothing found" and "I could not look"
//!
//! These must never render the same. A report that scanned nothing says so and
//! says why; a report carrying notes shows them and says the scan did not
//! complete cleanly. An empty table on its own always means "we looked, and
//! there was nothing there".

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::config::Config;
use crate::findings::{Store, SUPPRESSIONS_NOTE_SUFFIX};
use crate::model::{Alert, Calibration, Confidence, Finding, Report};
use crate::{daemon, Result};

/// A badge sits beside a branch or an agent name. Six display columns is the
/// budget; anything longer starts pushing its neighbour out of view.
pub const BADGE_COLUMNS: usize = 6;
pub const DEFAULT_COLUMNS: usize = 80;
pub const MIN_COLUMNS: usize = 20;

// Marks. Both are single-column, plain-text (no variation selector, so no
// terminal renders them as double-width emoji), and they differ in *shape*
// rather than only in colour — the colour of a badge comes from the user's
// `config.toml`, and a user who has not run `--setup` has none at all.
//
//   ⚠  a provider credential. The one mark every reader already parses as
//      "stop and look", and the same triangle collide uses for its own loudest
//      state, so a sidebar carrying both plugins stays coherent.
//   ⚑  a weak match. A flag is "worth a glance", not "stop": it marks the
//      `.env`-style assignment heuristic, which is a hint and not a verified
//      credential, and it is distinguishable from ⚠ at a glance and at one
//      column wide.
//   ✓  acknowledged. Deliberately not used as a badge — a clear target writes
//      no badge at all — only in the findings table.
const SECRET_MARK: &str = "\u{26a0}";
const WEAK_MARK: &str = "\u{2691}";
const ACK_MARK: &str = "\u{2713}";
/// Selection caret in the watch pane. Also the anchor [`draw`] scrolls to, so
/// it must stay the first character of the selected line.
const SELECTED_MARK: &str = "\u{25b8}";
const ELLIPSIS: char = '\u{2026}';

const TITLE: &str = "redact \u{b7} findings";
const CALIBRATION_TITLE: &str = "redact \u{b7} calibration";

/// The short id column: [`Finding::short_id`] is six characters.
const ID_COLUMNS: usize = 6;

/// Gutter (2) + mark and its trailing space (2) + four two-column gaps.
const TABLE_OVERHEAD: usize = 2 + 2 + 4 * 2;

/// Floors for the flexible columns. Below the sum of these the table stops
/// being a table and each finding is stacked over two lines instead.
const TABLE_MINIMUMS: [usize; 5] = [ID_COLUMNS, 10, 8, 8, 3];

// ---------------------------------------------------------------------------
// Badge
// ---------------------------------------------------------------------------

/// Badge text for one target, e.g. `⚠ 2` or `⚑ 1`. Severity itself is carried
/// by the token *name*, not this string.
///
/// A clear target renders the empty string, which the daemon treats as "clear
/// the token" rather than "write an empty badge". It is deliberately not a tick
/// or a dash: a target with nothing to report should occupy no columns at all.
///
/// `count` is the number of findings *at that alert level*, which is what
/// `Report::alert_for_pane` returns.
pub fn badge(alert: Alert, count: usize) -> String {
    let mark = match alert {
        Alert::Clear => return String::new(),
        Alert::Weak => WEAK_MARK,
        Alert::Secret => SECRET_MARK,
    };

    // Zero has nothing to say; the mark alone is the whole message.
    let magnitude = u64::try_from(count).unwrap_or(u64::MAX);
    let text = if magnitude == 0 {
        mark.to_string()
    } else {
        format!("{mark} {}", abbreviate(magnitude))
    };

    // Belt and braces: `abbreviate` is bounded at four columns, so this only
    // ever fires if the marks change.
    truncate_right(&text, BADGE_COLUMNS)
}

/// Compact magnitude, never wider than four display columns: `999`, `1.2k`,
/// `12k`, `999k`, `1.2M`, `999M`, `1G+`. Rounding is truncation, so the badge
/// never overstates what was found.
pub fn abbreviate(n: u64) -> String {
    match n {
        0..=999 => n.to_string(),
        1_000..=9_999 => format!("{}.{}k", n / 1_000, (n % 1_000) / 100),
        10_000..=999_999 => format!("{}k", n / 1_000),
        1_000_000..=9_999_999 => format!("{}.{}M", n / 1_000_000, (n % 1_000_000) / 100_000),
        10_000_000..=999_999_999 => format!("{}M", n / 1_000_000),
        _ => "1G+".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Findings view
// ---------------------------------------------------------------------------

/// The findings view of one report at an explicit width.
///
/// No line in the result exceeds `columns` display columns, or [`MIN_COLUMNS`]
/// where that is larger — below that floor the layout stops trying to be pretty,
/// but it still never overflows.
pub fn report_text(report: &Report, columns: usize) -> String {
    render(report, columns, None)
}

/// Read-only calibration results at an explicit terminal width.
///
/// Rows aggregate by stable rule name and expose only the preview the scanner
/// already masked. The digest is identity material and is never rendered.
pub fn calibration_text(calibration: &Calibration, columns: usize) -> String {
    let width = columns.max(MIN_COLUMNS);
    let mut out = String::new();
    push_line(&mut out, CALIBRATION_TITLE, width);
    out.push('\n');

    for line in calibration_summary_lines(calibration) {
        push_wrapped(&mut out, "", "  ", &line, width);
    }

    if !calibration.hits.is_empty() {
        out.push('\n');
        push_calibration_table(&mut out, calibration, width);
    }
    out.push_str(&notes_section(&calibration.notes, width));
    out
}

fn calibration_summary_lines(calibration: &Calibration) -> Vec<String> {
    let mut lines = Vec::new();
    let total = calibration.hits.len();
    let incomplete = calibration.panes_unread > 0
        || calibration.panes_truncated > 0
        || !calibration.notes.is_empty();

    if total > 0 {
        lines.push(format!(
            "{} would have fired across {} scanned.",
            matches(total),
            panes(calibration.panes_scanned)
        ));
    } else if calibration.panes_scanned > 0 && !incomplete {
        lines.push(format!(
            "0 matches would have fired across {} scanned.",
            panes(calibration.panes_scanned)
        ));
    } else if calibration.panes_scanned > 0 {
        lines.push(format!(
            "0 matches were observed across {} scanned, but this calibration did not complete \
             cleanly. This is not a clean result.",
            panes(calibration.panes_scanned)
        ));
    } else if calibration.panes_unread > 0 {
        lines.push(format!(
            "0 matches were observed because calibration could not look: every one of the {} \
             selected for reading was unread. This is not a clean result.",
            panes(calibration.panes_unread)
        ));
    } else if calibration.panes_skipped > 0 {
        lines.push(format!(
            "0 matches were observed because calibration looked at no panes: {} skipped. Pass \
             --all-panes to include ordinary terminal panes.",
            panes(calibration.panes_skipped)
        ));
    } else {
        lines.push(
            "0 matches were observed because herdr reported no panes to calibrate.".to_string(),
        );
    }

    if calibration.panes_skipped > 0 && calibration.panes_scanned > 0 {
        lines.push(format!(
            "{} skipped: not running an agent, named in `ignore_panes`, or this pane.",
            panes(calibration.panes_skipped)
        ));
    }
    if calibration.panes_unread > 0 && calibration.panes_scanned > 0 {
        lines.push(format!(
            "{} could not be read at all, so output there was not calibrated.",
            panes(calibration.panes_unread)
        ));
    }
    if calibration.panes_truncated > 0 {
        lines.push(format!(
            "{} had more output than the line budget, so this calibration did not examine all \
             available output.",
            panes(calibration.panes_truncated)
        ));
    }
    if total > 0 && incomplete {
        lines.push(
            "This calibration did not complete cleanly, so the counts above are incomplete. The \
             notes at the end say what went wrong."
                .to_string(),
        );
    }
    lines
}

fn matches(count: usize) -> String {
    if count == 1 {
        "1 match".to_string()
    } else {
        format!("{count} matches")
    }
}

struct CalibrationAggregate {
    confidence: Confidence,
    count: usize,
    panes: BTreeSet<String>,
    sample: String,
}

struct CalibrationRow {
    rule: String,
    confidence: &'static str,
    count: usize,
    panes: usize,
    sample: String,
}

const CALIBRATION_OVERHEAD: usize = 10;
const CALIBRATION_MINIMUMS: [usize; 5] = [12, 10, 7, 5, 10];

fn calibration_rows(calibration: &Calibration) -> Vec<CalibrationRow> {
    let mut grouped: BTreeMap<String, CalibrationAggregate> = BTreeMap::new();
    for hit in &calibration.hits {
        let aggregate = grouped
            .entry(hit.matched.pattern.clone())
            .or_insert_with(|| CalibrationAggregate {
                confidence: hit.matched.confidence,
                count: 0,
                panes: BTreeSet::new(),
                sample: hit.matched.preview.clone(),
            });
        aggregate.count += 1;
        aggregate.panes.insert(hit.pane_id.clone());
    }

    let mut rows: Vec<CalibrationRow> = grouped
        .into_iter()
        .map(|(rule, aggregate)| CalibrationRow {
            rule,
            confidence: aggregate.confidence.as_str(),
            count: aggregate.count,
            panes: aggregate.panes.len(),
            sample: aggregate.sample,
        })
        .collect();
    rows.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.rule.cmp(&right.rule))
    });
    rows
}

fn push_calibration_table(out: &mut String, calibration: &Calibration, width: usize) {
    let rows = calibration_rows(calibration);
    if CALIBRATION_OVERHEAD + CALIBRATION_MINIMUMS.iter().sum::<usize>() > width {
        for row in rows {
            push_wrapped(
                out,
                "  ",
                "    ",
                &format!(
                    "{} \u{b7} {} \u{b7} {} in {}",
                    row.rule,
                    row.confidence,
                    matches(row.count),
                    panes(row.panes)
                ),
                width,
            );
            let sample_prefix = "    masked sample: ";
            let sample = truncate_right(
                &row.sample,
                width.saturating_sub(display_width(sample_prefix)),
            );
            push_line(out, &format!("{sample_prefix}{sample}"), width);
        }
        return;
    }

    let mut widths = [
        calibration_natural(&rows, "rule", |row| &row.rule),
        calibration_natural(&rows, "confidence", |row| row.confidence),
        display_width("matches").max(rows.iter().map(|row| digits(row.count)).max().unwrap_or(0)),
        display_width("panes").max(rows.iter().map(|row| digits(row.panes)).max().unwrap_or(0)),
        calibration_natural(&rows, "masked sample", |row| &row.sample),
    ];
    shrink_widths(
        &mut widths,
        &CALIBRATION_MINIMUMS,
        CALIBRATION_OVERHEAD,
        width,
    );

    push_line(
        out,
        &format!(
            "  {}  {}  {}  {}  {}",
            pad("rule", widths[0]),
            pad("confidence", widths[1]),
            pad("matches", widths[2]),
            pad("panes", widths[3]),
            pad("masked sample", widths[4]),
        ),
        width,
    );
    for row in rows {
        push_line(
            out,
            &format!(
                "  {}  {}  {}  {}  {}",
                pad(&row.rule, widths[0]),
                pad(row.confidence, widths[1]),
                pad(&row.count.to_string(), widths[2]),
                pad(&row.panes.to_string(), widths[3]),
                pad(&row.sample, widths[4]),
            ),
            width,
        );
    }
}

fn calibration_natural(
    rows: &[CalibrationRow],
    heading: &str,
    pick: impl Fn(&CalibrationRow) -> &str,
) -> usize {
    rows.iter()
        .map(|row| display_width(pick(row)))
        .chain(std::iter::once(display_width(heading)))
        .max()
        .unwrap_or(0)
}

fn digits(value: usize) -> usize {
    if value == 0 {
        1
    } else {
        value.ilog10() as usize + 1
    }
}

/// [`report_text`], plus the watch pane's selection caret.
fn render(report: &Report, columns: usize, selected: Option<usize>) -> String {
    let width = columns.max(MIN_COLUMNS);
    let mut out = String::new();
    push_line(&mut out, TITLE, width);

    out.push('\n');
    for line in summary_lines(report) {
        push_wrapped(&mut out, "", "  ", &line, width);
    }

    if !report.findings.is_empty() {
        out.push('\n');
        push_table(&mut out, report, width, selected);
        out.push('\n');
        push_legend(&mut out, report, width);
    }

    out.push_str(&notes_section(&report.notes, width));
    out
}

/// The prose half of the view: what was scanned, what was found, and whether
/// the scan can be trusted. Every state a report can be in has to be
/// distinguishable here in words, without reading the table.
fn summary_lines(report: &Report) -> Vec<String> {
    let mut lines = Vec::new();
    let total = report.findings.len();
    let acknowledged = report.findings.iter().filter(|f| f.acknowledged).count();
    let live = total - acknowledged;
    let suppressions = active_suppression_count(report);

    if total == 0 {
        // Four different reasons for an empty table, and the user has to be able
        // to tell them apart: we looked and it was clean, we tried and failed, we
        // were not allowed to look, or there was nothing to look at.
        //
        // The order matters. "We tried and failed" is checked before the
        // no-panes case, because a session where every read failed still has
        // panes — saying herdr reported none would be false as well as
        // contradicted by the line below it.
        if report.panes_scanned > 0 {
            lines.push(format!(
                "{} scanned, nothing found.",
                panes(report.panes_scanned)
            ));
        } else if report.panes_unread > 0 {
            lines.push(format!(
                "Nothing was scanned: every one of the {} we tried to read failed. This is not a \
                 clean session — it is a session nobody looked at.",
                panes(report.panes_unread)
            ));
        } else if report.panes_skipped > 0 {
            lines.push(format!(
                "Nothing was scanned: {} skipped. A pane is skipped when it is not running an \
                 agent, when the config's `ignore_panes` names it, or when it is this pane. Set \
                 `scan_all_panes` in the config file, or pass --all-panes, to scan every pane \
                 rather than only agent panes.",
                panes(report.panes_skipped)
            ));
        } else {
            lines.push(
                "Nothing was scanned: herdr reported no panes to read, so there was nothing \
                 to look at."
                    .to_string(),
            );
        }
    } else {
        lines.push(format!(
            "{live} unacknowledged and {acknowledged} acknowledged, from {} scanned.",
            panes(report.panes_scanned)
        ));
        if report.panes_skipped > 0 {
            lines.push(format!(
                "{} skipped: not running an agent, named in `ignore_panes`, or this pane.",
                panes(report.panes_skipped)
            ));
        }
    }
    if suppressions > 0 {
        lines.push(format!(
            "{suppressions}{SUPPRESSIONS_NOTE_SUFFIX} Each ignores one exact value for one rule, \
             globally across panes."
        ));
    }

    // Never folded into the skipped count. "We chose not to look" and "we tried
    // and failed" are opposite claims, and a reader who cannot tell them apart
    // will read a blind scan as a quiet one.
    if report.panes_unread > 0 {
        lines.push(format!(
            "{} could not be read at all, so anything printed there is unexamined. The notes at \
             the end say why.",
            panes(report.panes_unread)
        ));
    }

    if report.panes_truncated > 0 {
        lines.push(format!(
            "{} had more output than the line budget, so you are not seeing everything that \
             scrolled past there; raise `lines` to read further back.",
            panes(report.panes_truncated)
        ));
    }

    if report.notes.iter().any(|note| !is_suppression_note(note)) {
        // Deliberately does not contain the phrase "nothing found": a reader
        // skimming, or a script grepping, must not be able to take those two
        // words out of a report that says the opposite.
        lines.push(
            "This scan did not complete cleanly, so an empty result here does not mean there \
             was nothing there. The notes at the end say what went wrong."
                .to_string(),
        );
    }

    lines
}

fn active_suppression_count(report: &Report) -> usize {
    report
        .notes
        .iter()
        .find_map(|note| {
            note.strip_suffix(SUPPRESSIONS_NOTE_SUFFIX)
                .and_then(|count| count.parse().ok())
        })
        .unwrap_or(0)
}

fn is_suppression_note(note: &str) -> bool {
    note.strip_suffix(SUPPRESSIONS_NOTE_SUFFIX)
        .is_some_and(|count| count.parse::<usize>().is_ok())
}

fn panes(count: usize) -> String {
    if count == 1 {
        "1 pane".to_string()
    } else {
        format!("{count} panes")
    }
}

/// One line of the table, already reduced to strings.
struct Row {
    mark: &'static str,
    id: String,
    rule: String,
    pane: String,
    preview: String,
    age: String,
    agent: Option<String>,
    cwd: Option<String>,
    foreground_process_when_first_seen: Option<String>,
}

fn row_of(finding: &Finding, now: u64) -> Row {
    Row {
        mark: if finding.acknowledged {
            ACK_MARK
        } else {
            match Alert::from_confidence(finding.confidence) {
                Alert::Secret => SECRET_MARK,
                _ => WEAK_MARK,
            }
        },
        id: finding.short_id().to_string(),
        rule: finding.label.clone(),
        // The agent name where herdr reports one, the pane id otherwise. The
        // store recorded it at the time of the sighting, so a renamed agent
        // does not rewrite history.
        pane: finding.pane_label.clone(),
        agent: finding.agent.clone(),
        cwd: finding.cwd.as_ref().map(|cwd| cwd.display().to_string()),
        foreground_process_when_first_seen: match (
            finding.foreground_process_name_when_first_seen.as_deref(),
            finding.foreground_process_pid_when_first_seen,
        ) {
            (Some(name), Some(pid)) => Some(format!("{name} (pid {pid})")),
            (Some(name), None) => Some(name.to_string()),
            (None, Some(pid)) => Some(format!("pid {pid}")),
            (None, None) => None,
        },
        preview: finding.preview.clone(),
        age: age(now, finding.first_seen),
    }
}

/// The findings table. The vector arrives sorted — unacknowledged first, then
/// most recent first — and is rendered in that order; re-sorting here would put
/// the renderer and the store in disagreement about what "first" means.
fn push_table(out: &mut String, report: &Report, width: usize, selected: Option<usize>) {
    let rows: Vec<Row> = report
        .findings
        .iter()
        .map(|finding| row_of(finding, report.generated_at))
        .collect();

    if TABLE_OVERHEAD + TABLE_MINIMUMS.iter().sum::<usize>() > width {
        push_stacked(out, &rows, width, selected);
        return;
    }

    let mut widths = [
        ID_COLUMNS,
        natural(&rows, "rule", |row| &row.rule),
        natural(&rows, "pane", |row| &row.pane),
        natural(&rows, "preview", |row| &row.preview),
        natural(&rows, "age", |row| &row.age),
    ];
    shrink(&mut widths, width);

    push_line(
        out,
        &format!(
            "    {}  {}  {}  {}  {}",
            pad("id", widths[0]),
            pad("rule", widths[1]),
            pad("pane", widths[2]),
            pad("preview", widths[3]),
            pad("age", widths[4]),
        ),
        width,
    );

    for (index, row) in rows.iter().enumerate() {
        let gutter = if selected == Some(index) {
            format!("{SELECTED_MARK} ")
        } else {
            "  ".to_string()
        };
        push_line(
            out,
            &format!(
                "{gutter}{} {}  {}  {}  {}  {}",
                row.mark,
                pad(&row.id, widths[0]),
                pad(&row.rule, widths[1]),
                pad(&row.pane, widths[2]),
                pad(&row.preview, widths[3]),
                pad(&row.age, widths[4]),
            ),
            width,
        );
    }
}

/// The narrow-pane fallback: each finding is stacked rather than squeezed
/// into a table, with provenance on following lines when it was available.
fn push_stacked(out: &mut String, rows: &[Row], width: usize, selected: Option<usize>) {
    for (index, row) in rows.iter().enumerate() {
        let gutter = if selected == Some(index) {
            format!("{SELECTED_MARK} ")
        } else {
            "  ".to_string()
        };
        push_line(
            out,
            &format!("{gutter}{} {}  {}", row.mark, row.id, row.rule),
            width,
        );
        push_line(
            out,
            &format!(
                "      {} \u{b7} {} \u{b7} {}",
                row.pane, row.preview, row.age
            ),
            width,
        );
        if let Some(agent) = &row.agent {
            push_wrapped(
                out,
                "      ",
                "        ",
                &format!("agent when first seen: {agent}"),
                width,
            );
        }
        if let Some(cwd) = &row.cwd {
            push_wrapped(
                out,
                "      ",
                "        ",
                &format!("working directory when first seen: {cwd}"),
                width,
            );
        }
        if let Some(process) = &row.foreground_process_when_first_seen {
            push_wrapped(
                out,
                "      ",
                "        ",
                &format!("foreground process when first seen: {process}"),
                width,
            );
        }
    }
}

fn push_legend(out: &mut String, report: &Report, width: usize) {
    push_line(out, "legend", width);
    push_line(
        out,
        &format!("  {SECRET_MARK}  a provider credential, not acknowledged"),
        width,
    );
    push_line(
        out,
        &format!("  {WEAK_MARK}  a weak match, not acknowledged"),
        width,
    );
    if report.findings.iter().any(|f| f.acknowledged) {
        push_line(
            out,
            &format!("  {ACK_MARK}  acknowledged \u{2014} the value is still in that scrollback"),
            width,
        );
    }
    push_wrapped(
        out,
        "  ",
        "  ",
        "age is how long ago the finding was first seen. The preview is masked: at most the \
         first four and last four characters ever leave the scanner.",
        width,
    );
}

/// Non-fatal problems this cycle collected — a pane that vanished, a rule that
/// would not compile, a read that failed. They belong on screen: silently
/// dropping them renders as a suspiciously clean report.
fn notes_section(notes: &[String], width: usize) -> String {
    let visible: Vec<&String> = notes
        .iter()
        .filter(|note| !is_suppression_note(note))
        .collect();
    let mut out = String::new();
    if visible.is_empty() {
        return out;
    }
    out.push('\n');
    push_line(&mut out, "notes", width);
    for note in visible {
        push_wrapped(&mut out, "  ", "    ", note, width);
    }
    out
}

/// Widest of a column's cells and its heading.
fn natural(rows: &[Row], heading: &str, pick: impl Fn(&Row) -> &str) -> usize {
    rows.iter()
        .map(|row| display_width(pick(row)))
        .chain(std::iter::once(display_width(heading)))
        .max()
        .unwrap_or(0)
}

/// Shrinks the flexible columns until the table fits, always taking the column
/// with the most slack first so no single column collapses while another is
/// still luxurious. Stops at the floors, which the caller has already checked
/// will fit.
fn shrink(widths: &mut [usize; 5], width: usize) {
    shrink_widths(widths, &TABLE_MINIMUMS, TABLE_OVERHEAD, width);
}

fn shrink_widths<const N: usize>(
    widths: &mut [usize; N],
    minimums: &[usize; N],
    overhead: usize,
    width: usize,
) {
    loop {
        if overhead + widths.iter().sum::<usize>() <= width {
            return;
        }
        let widest = (0..widths.len())
            .filter(|&index| widths[index] > minimums[index])
            .max_by_key(|&index| widths[index] - minimums[index]);
        match widest {
            Some(index) => widths[index] -= 1,
            None => return,
        }
    }
}

/// How long ago, in at most five display columns. `first_seen` is what a
/// finding ages by, because a finding lives until it is acknowledged.
fn age(now: u64, first_seen: u64) -> String {
    let seconds = now.saturating_sub(first_seen);
    match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3_599 => format!("{}m", seconds / 60),
        3_600..=86_399 => format!("{}h", seconds / 3_600),
        _ => match seconds / 86_400 {
            days @ 0..=999 => format!("{days}d"),
            // A clock that jumped, or a state file from another era. Say
            // "a very long time" rather than printing a nine-digit column.
            _ => "999d+".to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// Machine-readable snapshot, with the same masking as everything else.
///
/// The counts and the notes travel with it on purpose: a scripted consumer has
/// to be able to tell "clean" from "the scan failed", and an empty `findings`
/// array on its own cannot say which it was.
///
/// `digest` is deliberately absent. It is identity for the store, never
/// something to render, and a keyed hash of a credential is not a thing to hand
/// to a script that might log it.
pub fn report_json(report: &Report) -> String {
    let findings: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|finding| {
            let mut value = json!({
                "id": finding.id,
                "short_id": finding.short_id(),
                "pattern": finding.pattern,
                "label": finding.label,
                "confidence": finding.confidence.as_str(),
                "preview": finding.preview,
                "value_len": finding.value_len,
                "pane_id": finding.pane_id,
                "pane_label": finding.pane_label,
                "workspace_id": finding.workspace_id,
                "line": finding.line,
                "first_seen": finding.first_seen,
                "last_seen": finding.last_seen,
                "age_seconds": report.generated_at.saturating_sub(finding.first_seen),
                "acknowledged": finding.acknowledged,
            });
            if let Some(object) = value.as_object_mut() {
                if let Some(agent) = &finding.agent {
                    object.insert("agent".to_string(), json!(agent));
                }
                if let Some(cwd) = &finding.cwd {
                    object.insert("cwd".to_string(), json!(cwd.display().to_string()));
                }
                if let Some(name) = &finding.foreground_process_name_when_first_seen {
                    object.insert(
                        "foreground_process_name_when_first_seen".to_string(),
                        json!(name),
                    );
                }
                if let Some(pid) = finding.foreground_process_pid_when_first_seen {
                    object.insert(
                        "foreground_process_pid_when_first_seen".to_string(),
                        json!(pid),
                    );
                }
            }
            value
        })
        .collect();

    let acknowledged = report.findings.iter().filter(|f| f.acknowledged).count();
    let suppressions = active_suppression_count(report);
    let notes: Vec<&String> = report
        .notes
        .iter()
        .filter(|note| !is_suppression_note(note))
        .collect();
    let value = json!({
        // Bumped only when a key changes meaning, so a script can refuse a
        // shape it does not understand rather than misread it.
        "version": 1,
        "generated_at": report.generated_at,
        "alert": alert_name(report.alert()),
        "counts": {
            "findings": report.findings.len(),
            "unacknowledged": report.findings.len() - acknowledged,
            "acknowledged": acknowledged,
            "suppressions": suppressions,
            "panes_scanned": report.panes_scanned,
            "panes_skipped": report.panes_skipped,
            "panes_unread": report.panes_unread,
            "panes_truncated": report.panes_truncated,
            "notes": notes.len(),
        },
        "notes": notes,
        "findings": findings,
    });

    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

fn alert_name(alert: Alert) -> &'static str {
    match alert {
        Alert::Clear => "clear",
        Alert::Weak => "weak",
        Alert::Secret => "secret",
    }
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

/// Width of `text` in terminal display columns.
///
/// ANSI CSI escape sequences are stripped and count zero; everything else is
/// measured by `unicode-width`, which implements UAX #11 plus the emoji rules.
///
/// This used to be a hand-rolled range table, and it was wrong in six ways a
/// reviewer found in one sitting: `🚀` measured one column because it sits above
/// the 1F300–1F64F block, `👍🏽` measured four because the skin-tone modifier was
/// counted separately, a ZWJ family sequence measured six, and Hebrew points and
/// Thai vowel signs measured one instead of zero. Under-counting is the
/// dangerous direction: every layout promise in this file is "no line exceeds
/// the width it was given", and a ruler that reads short breaks all of them at
/// once.
pub fn display_width(text: &str) -> usize {
    use unicode_width::UnicodeWidthStr;

    let mut visible = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            // CSI: ESC [ … final byte in 0x40..=0x7e.
            if chars.peek() == Some(&'[') {
                chars.next();
                for tail in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&tail) {
                        break;
                    }
                }
            }
            continue;
        }
        if ch.is_control() {
            continue;
        }
        visible.push(ch);
    }
    // Measured over the whole string rather than character by character, which
    // is what lets a ZWJ sequence or a skin-tone modifier count once.
    UnicodeWidthStr::width(visible.as_str())
}

/// Trims `text` to `max` display columns from the right, marking the cut with
/// `…`. Everything in this view has its informative half at the front: a rule
/// label, an agent name, a masked preview whose leading characters are the ones
/// that identify the provider.
pub fn truncate_right(text: &str, max: usize) -> String {
    if display_width(text) <= max {
        return text.to_string();
    }
    if max == 0 {
        return String::new();
    }
    if max == 1 {
        return ELLIPSIS.to_string();
    }

    let budget = max - 1;
    let mut out = String::new();
    for ch in text.chars() {
        // Measured by re-widening the whole prefix rather than by adding up
        // per-character widths. A grapheme cluster — a skin-tone modifier, a ZWJ
        // sequence — is not the sum of its characters' widths, and the sum is
        // always the larger of the two, so per-character accounting cuts short
        // rather than long. It still has to be measured as a whole or the cut
        // itself can land mid-cluster.
        out.push(ch);
        if display_width(&out) > budget {
            out.pop();
            break;
        }
    }
    out.push(ELLIPSIS);
    out
}

/// Truncates to `width` columns and pads to exactly that many.
fn pad(text: &str, width: usize) -> String {
    let mut out = truncate_right(text, width);
    let used = display_width(&out);
    out.push_str(&" ".repeat(width.saturating_sub(used)));
    out
}

fn push_line(out: &mut String, line: &str, width: usize) {
    let trimmed = line.trim_end();
    out.push_str(&truncate_right(trimmed, width));
    out.push('\n');
}

/// Greedy word wrap. Prose wraps rather than truncates, because truncating an
/// explanation removes the explanation.
fn push_wrapped(out: &mut String, first: &str, rest: &str, text: &str, width: usize) {
    let mut prefix = first;
    let mut line = String::new();

    for word in text.split_whitespace() {
        let budget = width.saturating_sub(display_width(prefix)).max(1);
        let candidate = if line.is_empty() {
            word.to_string()
        } else {
            format!("{line} {word}")
        };
        if display_width(&candidate) <= budget || line.is_empty() {
            line = candidate;
        } else {
            push_line(out, &format!("{prefix}{line}"), width);
            prefix = rest;
            line = word.to_string();
        }
    }
    if !line.is_empty() {
        push_line(out, &format!("{prefix}{line}"), width);
    }
}

// ---------------------------------------------------------------------------
// One-shot verbs
// ---------------------------------------------------------------------------

pub fn run_calibrate(config: &Config) -> Result<()> {
    let calibration = daemon::calibrate(config)?;
    let width = terminal_size().0;
    print!("{}", calibration_text(&calibration, width));
    Ok(())
}

pub fn run_once(config: &Config) -> Result<()> {
    let report = daemon::scan_once(config)?;
    let width = terminal_size().0;
    let mut out = report_text(&report, width);
    out.push('\n');
    push_wrapped(
        &mut out,
        "",
        "  ",
        &watcher_line(config),
        width.max(MIN_COLUMNS),
    );
    print!("{out}");
    Ok(())
}

pub fn run_json(config: &Config) -> Result<()> {
    let report = daemon::scan_once(config)?;
    println!("{}", report_json(&report));
    Ok(())
}

/// Whether anything is watching between one-shot runs.
///
/// Deliberately *not* a `Report` note: notes are problems this scan hit, and
/// the summary reads "this scan did not complete cleanly" whenever there are
/// any. The watcher being off is context, not a failure.
fn watcher_line(config: &Config) -> String {
    if daemon::live_pid().is_some() {
        return format!(
            "The background watcher is running and rescans every {} seconds.",
            config.interval.as_secs()
        );
    }
    if daemon::is_enabled() {
        return "The background watcher is enabled but is not running, so nothing is being \
                scanned between these runs \u{2014} `redact --restore` starts it."
            .to_string();
    }
    "The background watcher is off, so nothing is scanned between these runs \u{2014} \
     `redact --enable` starts it."
        .to_string()
}

// ---------------------------------------------------------------------------
// Watch pane
// ---------------------------------------------------------------------------

const CLEAR_SCREEN: &str = "\u{1b}[H\u{1b}[2J";
const HIDE_CURSOR: &str = "\u{1b}[?25l";
const SHOW_CURSOR: &str = "\u{1b}[?25h";
const RESET_ATTRS: &str = "\u{1b}[0m";

/// How often the loop wakes to look at the keyboard and at the stop flag. The
/// refresh interval is a multiple of this rather than a single long sleep, so a
/// keystroke is never held for a whole cycle.
const TICK: Duration = Duration::from_millis(80);

/// Live findings pane: `a` acknowledges the selected finding, `s` acknowledges
/// it and permanently suppresses its exact value, `A` acknowledges them all,
/// `q` quits, and `j`/`k` and the arrow keys move the selection.
///
/// This runs inside a herdr overlay pane, so it clears and redraws in place
/// rather than scrolling, sizes itself from the real terminal every frame, and
/// puts the terminal back the way it found it on the way out.
///
/// If stdin is not a terminal — a piped pane, a log capture — it degrades to a
/// plain refresh loop with no key handling rather than failing. A pane whose
/// stdin is a pipe still deserves to render.
pub fn run_watch(config: &Config) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    register_stop_signals(&stop)?;

    let mut out = std::io::stdout();
    let _ = write!(out, "{HIDE_CURSOR}");
    let _ = out.flush();

    // Raw mode for as long as this value lives, and not one instant longer:
    // dropped below on every path out of the loop, restored by a panic hook if
    // the process dies without unwinding, and restored by the signal path
    // because the handlers only set a flag the loop reads.
    let keyboard = tty::Keyboard::open();
    let interactive = keyboard.is_some();

    let result = watch_loop(config, &stop, &mut out, interactive);

    drop(keyboard);
    // Best effort, and deliberately unconditional: whatever went wrong, the
    // terminal goes back the way we found it.
    let _ = write!(out, "{SHOW_CURSOR}{RESET_ATTRS}");
    let _ = out.flush();
    result
}

fn watch_loop(
    config: &Config,
    stop: &AtomicBool,
    out: &mut impl Write,
    interactive: bool,
) -> Result<()> {
    let mut report: Option<Report> = None;
    let mut error: Option<String> = None;
    let mut status: Option<String> = None;
    let mut selected = 0usize;
    let mut due = true;
    let mut redraw = true;
    let mut last_scan = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        if due {
            match daemon::scan_once(config) {
                Ok(fresh) => {
                    report = Some(fresh);
                    error = None;
                }
                // A failed cycle keeps the last good frame on screen under an
                // explicit error line, rather than blanking to "nothing found".
                Err(err) => error = Some(err.to_string()),
            }
            last_scan = Instant::now();
            due = false;
            redraw = true;
        }

        if let Some(report) = &report {
            selected = clamp_selection(selected, report.findings.len());
        }

        if redraw {
            let (columns, rows) = terminal_size();
            let frame = frame(
                config,
                report.as_ref(),
                error.as_deref(),
                status.as_deref(),
                columns,
                interactive,
                selected,
            );
            draw(out, &frame, rows)?;
            redraw = false;
        }

        if interactive {
            for key in tty::poll_keys(TICK) {
                match key {
                    tty::Key::Quit => return Ok(()),
                    tty::Key::Up => {
                        selected = selected.saturating_sub(1);
                        redraw = true;
                    }
                    tty::Key::Down => {
                        selected = selected.saturating_add(1);
                        redraw = true;
                    }
                    tty::Key::Ack => {
                        status = Some(acknowledge_selected(config, report.as_ref(), selected));
                        due = true;
                    }
                    tty::Key::Suppress => {
                        status = Some(suppress_selected(config, report.as_ref(), selected));
                        due = true;
                    }
                    tty::Key::AckAll => {
                        status = Some(acknowledge_all(config));
                        due = true;
                    }
                }
            }
        } else {
            std::thread::sleep(TICK);
        }

        if last_scan.elapsed() >= config.interval {
            due = true;
        }
    }
    Ok(())
}

fn clamp_selection(selected: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else {
        selected.min(len - 1)
    }
}

/// Acknowledging goes through the store and is saved immediately, so the
/// daemon, the CLI and this pane never disagree about what has been dismissed.
fn acknowledge_selected(config: &Config, report: Option<&Report>, selected: usize) -> String {
    let Some(finding) = report.and_then(|report| report.findings.get(selected)) else {
        return "nothing to acknowledge.".to_string();
    };
    let id = finding.id.clone();
    let short = finding.short_id().to_string();
    let mut store = Store::load(config);
    let count = store.acknowledge(&id);
    if count == 0 {
        return format!("{short} is no longer in the store.");
    }
    match store.save() {
        Ok(()) => format!("acknowledged {short}."),
        Err(err) => format!("could not save the acknowledgement of {short}: {err}"),
    }
}

fn suppress_selected(config: &Config, report: Option<&Report>, selected: usize) -> String {
    let Some(finding) = report.and_then(|report| report.findings.get(selected)) else {
        return "nothing to suppress.".to_string();
    };
    let id = finding.id.clone();
    let short = finding.short_id().to_string();
    let mut store = Store::load(config);
    let count = store.suppress(&id);
    if count == 0 {
        return format!("{short} is no longer in the store.");
    }
    match store.save() {
        Ok(()) => format!(
            "suppressed {short} permanently; this exact value will be ignored globally across \
             panes."
        ),
        Err(err) => format!("could not save the permanent suppression of {short}: {err}"),
    }
}

fn acknowledge_all(config: &Config) -> String {
    let mut store = Store::load(config);
    let count = store.acknowledge_all();
    match store.save() {
        Ok(()) => format!("acknowledged {count} finding(s)."),
        Err(err) => format!("could not save the acknowledgements: {err}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn frame(
    config: &Config,
    report: Option<&Report>,
    error: Option<&str>,
    status: Option<&str>,
    columns: usize,
    interactive: bool,
    selected: usize,
) -> String {
    let width = columns.max(MIN_COLUMNS);
    let mut out = match report {
        Some(report) => render(report, columns, interactive.then_some(selected)),
        None => match error {
            Some(err) => return error_frame(err, columns),
            None => {
                let mut out = String::new();
                push_line(&mut out, TITLE, width);
                out.push('\n');
                push_wrapped(&mut out, "", "", "Scanning\u{2026}", width);
                return out;
            }
        },
    };

    if let Some(err) = error {
        out.push('\n');
        push_wrapped(
            &mut out,
            "",
            "  ",
            &format!("The last refresh failed, so this is the previous scan: {err}"),
            width,
        );
    }
    if let Some(status) = status {
        out.push('\n');
        push_wrapped(&mut out, "", "  ", status, width);
    }

    out.push('\n');
    push_wrapped(&mut out, "", "  ", &watcher_line(config), width);
    let keys = if interactive {
        "a acknowledge · s suppress exact value permanently · A acknowledge all · j/k or arrows \
         move · q quit"
    } else {
        "stdin is not a terminal here, so keys are disabled; this pane only refreshes."
    };
    push_wrapped(&mut out, "", "  ", keys, width);
    out
}

fn error_frame(message: &str, columns: usize) -> String {
    let width = columns.max(MIN_COLUMNS);
    let mut out = String::new();
    push_line(&mut out, TITLE, width);
    out.push('\n');
    push_wrapped(
        &mut out,
        "",
        "",
        "Could not scan. This is not a clean result \u{2014} nothing was looked at:",
        width,
    );
    push_wrapped(&mut out, "  ", "  ", message, width);
    out.push('\n');
    push_wrapped(&mut out, "", "", "Retrying on the next refresh.", width);
    out
}

/// Clears and redraws in place. When the frame is taller than the pane, the
/// window follows the selection caret: a selected row the user cannot see is
/// the same as no selection at all.
fn draw(out: &mut impl Write, frame: &str, rows: usize) -> Result<()> {
    // One line is left free so the last row cannot scroll the screen up.
    let budget = rows.saturating_sub(1).max(1);
    let lines: Vec<&str> = frame.lines().collect();

    let mut buffer = String::with_capacity(frame.len() + 64);
    buffer.push_str(CLEAR_SCREEN);

    if lines.len() <= budget {
        for line in &lines {
            buffer.push_str(line);
            buffer.push('\n');
        }
    } else {
        // The title stays pinned; the rest scrolls under it, and one line is
        // spent saying how much is off screen.
        let body = &lines[1.min(lines.len())..];
        let show = budget.saturating_sub(2).max(1).min(body.len());
        let anchor = lines
            .iter()
            .position(|line| line.starts_with(SELECTED_MARK))
            .unwrap_or(1)
            .saturating_sub(1);
        let start = if anchor >= show { anchor + 1 - show } else { 0 }.min(body.len() - show);

        buffer.push_str(lines[0]);
        buffer.push('\n');
        for line in &body[start..start + show] {
            buffer.push_str(line);
            buffer.push('\n');
        }
        let hidden = body.len() - show;
        buffer.push_str(&format!("... {hidden} more lines\n"));
    }

    out.write_all(buffer.as_bytes())?;
    out.flush()?;
    Ok(())
}

#[cfg(unix)]
fn register_stop_signals(stop: &Arc<AtomicBool>) -> Result<()> {
    // SIGHUP as well as the usual two: a herdr overlay pane that is closed
    // takes its terminal with it, and the loop has to notice and put the
    // terminal back rather than dying mid-frame.
    for signal in [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ] {
        signal_hook::flag::register(signal, Arc::clone(stop))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn register_stop_signals(_stop: &Arc<AtomicBool>) -> Result<()> {
    Ok(())
}

/// Terminal size in (columns, rows). The pane may be narrower than we would
/// like, so this is read every frame rather than cached.
fn terminal_size() -> (usize, usize) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        let fd = std::io::stdout().as_raw_fd();
        // SAFETY: `size` is a correctly sized, owned `winsize`.
        let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) };
        if rc == 0 && size.ws_col > 0 {
            let rows = if size.ws_row > 0 {
                size.ws_row as usize
            } else {
                24
            };
            return (size.ws_col as usize, rows);
        }
    }
    env_terminal_size()
}

fn env_terminal_size() -> (usize, usize) {
    let columns = crate::config::non_empty_env("COLUMNS")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|c| *c > 0)
        .unwrap_or(DEFAULT_COLUMNS);
    let rows = crate::config::non_empty_env("LINES")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|r| *r > 0)
        .unwrap_or(24);
    (columns, rows)
}

// ---------------------------------------------------------------------------
// Keyboard
// ---------------------------------------------------------------------------

/// Raw-mode keyboard input with no extra dependency.
///
/// The rule this module exists to hold: **the terminal is restored on every
/// exit path.** Three of them, and all three are covered here rather than at
/// the call site, because a plugin pane that leaves a terminal in raw mode is
/// unforgivable:
///
///   * a normal return, or `q` \u{2014} `Keyboard` is dropped;
///   * a signal \u{2014} the handlers only set a flag, so the loop returns
///     normally and `Keyboard` is still dropped;
///   * a panic \u{2014} a panic hook restores the saved settings. The release
///     profile aborts on panic, so `Drop` is not run then and the hook is the
///     only thing standing between a bug and a wrecked terminal.
///
/// The mode entered is cbreak, not full raw: `ISIG` is deliberately left on, so
/// Ctrl-C still raises `SIGINT` and takes the ordinary shutdown path. Ctrl-C is
/// also accepted as a byte, for a terminal where it arrives that way.
#[cfg(unix)]
mod tty {
    use std::io::Read;
    use std::sync::{Mutex, Once, OnceLock};
    use std::time::Duration;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Key {
        Up,
        Down,
        Ack,
        Suppress,
        AckAll,
        Quit,
    }

    /// The settings to put back, and the descriptor to put them back on. Global
    /// because the panic hook cannot be handed a reference to a local.
    static SAVED: OnceLock<Mutex<Option<(i32, libc::termios)>>> = OnceLock::new();
    static HOOK: Once = Once::new();

    fn saved() -> &'static Mutex<Option<(i32, libc::termios)>> {
        SAVED.get_or_init(|| Mutex::new(None))
    }

    /// Puts the terminal back. Idempotent: the saved settings are taken, so a
    /// second call (drop after the panic hook already ran, say) does nothing.
    fn restore() {
        let Ok(mut slot) = saved().lock() else {
            return;
        };
        if let Some((fd, settings)) = slot.take() {
            // SAFETY: `fd` was a terminal when the settings were read from it,
            // and `settings` is exactly what was read.
            unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &settings) };
        }
    }

    pub struct Keyboard {
        _private: (),
    }

    impl Keyboard {
        /// Puts stdin into cbreak mode, or returns `None` when stdin is not a
        /// terminal — a piped pane degrades to a refresh-only view rather than
        /// failing.
        pub fn open() -> Option<Self> {
            let fd = libc::STDIN_FILENO;
            // SAFETY: plain queries on a descriptor this process owns.
            if unsafe { libc::isatty(fd) } != 1 {
                return None;
            }
            let mut settings: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(fd, &mut settings) } != 0 {
                return None;
            }
            let original = settings;

            // Characters arrive as they are typed and are not echoed into the
            // frame. VMIN/VTIME 0 makes the read non-blocking, which is what
            // lets one loop serve both the keyboard and the refresh interval.
            settings.c_lflag &= !(libc::ICANON | libc::ECHO);
            settings.c_cc[libc::VMIN] = 0;
            settings.c_cc[libc::VTIME] = 0;
            // SAFETY: `settings` is the descriptor's own settings, modified.
            if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &settings) } != 0 {
                return None;
            }

            if let Ok(mut slot) = saved().lock() {
                *slot = Some((fd, original));
            }
            HOOK.call_once(|| {
                let previous = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |info| {
                    restore();
                    previous(info);
                }));
            });
            Some(Self { _private: () })
        }
    }

    impl Drop for Keyboard {
        fn drop(&mut self) {
            restore();
        }
    }

    /// Waits up to `timeout` for input and decodes whatever arrived. Returns an
    /// empty vector on a timeout, which is the normal case.
    pub fn poll_keys(timeout: Duration) -> Vec<Key> {
        let mut poll = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: one correctly initialised `pollfd`, and a count that matches.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready <= 0 {
            return Vec::new();
        }

        let mut buffer = [0u8; 64];
        let read = match std::io::stdin().read(&mut buffer) {
            Ok(0) => return vec![Key::Quit], // stdin closed under us
            Ok(read) => read,
            Err(_) => return Vec::new(),
        };
        decode(&buffer[..read])
    }

    /// Decodes a burst of bytes into keys. Arrow keys arrive as `ESC [ A`, and
    /// anything else beginning with `ESC` is skipped rather than guessed at.
    fn decode(bytes: &[u8]) -> Vec<Key> {
        let mut keys = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                0x1b if bytes.get(index + 1) == Some(&b'[') => {
                    match bytes.get(index + 2) {
                        Some(b'A') => keys.push(Key::Up),
                        Some(b'B') => keys.push(Key::Down),
                        _ => {}
                    }
                    index += 3;
                    continue;
                }
                b'q' | b'Q' | 0x03 => keys.push(Key::Quit),
                b'a' => keys.push(Key::Ack),
                b's' => keys.push(Key::Suppress),
                b'A' => keys.push(Key::AckAll),
                b'j' => keys.push(Key::Down),
                b'k' => keys.push(Key::Up),
                _ => {}
            }
            index += 1;
        }
        keys
    }

    #[cfg(test)]
    mod tests {
        use super::{decode, Key};

        #[test]
        fn arrows_and_letters_both_move_the_selection() {
            assert_eq!(decode(b"j"), vec![Key::Down]);
            assert_eq!(decode(b"k"), vec![Key::Up]);
            assert_eq!(decode(b"\x1b[B"), vec![Key::Down]);
            assert_eq!(decode(b"\x1b[A"), vec![Key::Up]);
        }

        #[test]
        fn acknowledging_one_is_not_acknowledging_all() {
            assert_eq!(decode(b"a"), vec![Key::Ack]);
            assert_eq!(decode(b"A"), vec![Key::AckAll]);
            assert_eq!(decode(b"s"), vec![Key::Suppress]);
        }

        #[test]
        fn an_unknown_escape_sequence_is_ignored_rather_than_guessed() {
            // Home, in one of its several spellings. Nothing should move.
            assert!(decode(b"\x1b[H").is_empty());
        }

        #[test]
        fn ctrl_c_quits_even_where_it_arrives_as_a_byte() {
            assert_eq!(decode(b"\x03"), vec![Key::Quit]);
            assert_eq!(decode(b"q"), vec![Key::Quit]);
        }
    }
}

/// Non-Unix has no terminal handling here: the plugin declares Linux and macOS,
/// and a keyboardless build still renders and refreshes.
#[cfg(not(unix))]
mod tty {
    use std::time::Duration;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Key {
        Up,
        Down,
        Ack,
        Suppress,
        AckAll,
        Quit,
    }

    pub struct Keyboard {
        _private: (),
    }

    impl Keyboard {
        pub fn open() -> Option<Self> {
            None
        }
    }

    pub fn poll_keys(_timeout: Duration) -> Vec<Key> {
        Vec::new()
    }
}
