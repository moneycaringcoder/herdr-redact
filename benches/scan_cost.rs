//! Measures the pure `redact::scan::scan` function over pane text already in
//! memory and the recurring cost of loading config plus compiling its rules.
//! Run it with `cargo bench --bench scan_cost`. Cargo's bench profile inherits
//! the shipped `[profile.release]`, including `opt-level = "z"` and LTO, so
//! these are the costs the shipped binary actually gets.
//!
//! Every corpus is generated once, checked once, and only then timed. The
//! `clean_400` case uses 3 warmups and 11 measured runs; `clean_5k` uses 3 and
//! 9; `clean_20k`, `sparse_20k`, `matchy_5k`, and `one_megabyte_line` each use
//! 2 and 7. The table reports the median measured run so occasional scheduler
//! noise does not own the result, and also shows the minimum as a useful lower
//! bound when comparing machines or later revisions.
//! Config loading and compilation use 10 warmups and 51 measured runs against a
//! representative file with the shipped packs, three custom patterns, and two
//! allowlist expressions.
//!
//! A secret value must never leave the scanner, and a durable benchmark fixture
//! is no exception. Positive fixtures therefore use only documented,
//! obviously-synthetic `...EXAMPLE` shapes or `bench_...` weak candidates; none
//! could have been issued by a provider. This benchmark is deliberately not a
//! required CI gate: timing on shared runners is noisy, and a noisy required
//! performance gate is worse than having no gate. Humans should compare the
//! printed measurements under controlled conditions instead.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use redact::config::{self, MIN_INTERVAL_SECONDS};
use redact::model::DigestKey;
use redact::scan::{scan, Rules};

const KEY: DigestKey = [
    0x5a, 0x11, 0x9c, 0x03, 0x7e, 0xd2, 0x48, 0x6b, 0x91, 0x0f, 0xa4, 0x33, 0xc8, 0x27, 0x5e, 0xe1,
];
const ONE_MIB: usize = 1024 * 1024;
const MINIMUM_CYCLE_BUDGET: Duration = Duration::from_secs(30);
const CONFIG_WARMUPS: usize = 10;
const CONFIG_MEASURED: usize = 51;
const BENCH_CONFIG: &str = r#"{
  "interval_seconds": 1,
  "rule_packs": ["default", "narrow"],
  "patterns": [
    {
      "name": "bench_internal_api_key",
      "regex": "\\bbench_[A-Za-z0-9]{32}\\b",
      "strong": true
    },
    {
      "name": "bench_service_token",
      "regex": "\\bsvc_[a-f0-9]{40}\\b",
      "strong": true
    },
    {
      "name": "bench_deployment_hint",
      "regex": "\\bdeploy_[A-Za-z0-9_-]{24,48}\\b",
      "strong": false
    }
  ],
  "allowlist": ["EXAMPLE$", "^test_"]
}"#;

/// The body of the synthetic token, without the checksum GitHub's format
/// requires. Kept apart from its checksum so the benchmark holds no complete
/// token: the rule verifies GitHub's checksum, so a complete one would be a
/// structurally valid credential sitting in the repository, and this file — a
/// timing harness — is no place for one.
const SYNTHETIC_GITHUB_BODY: &str = "0123456789abcdefghijklmnopqrst";

/// The synthetic token, assembled with the checksum GitHub's format requires:
/// the last six characters are the CRC-32 of everything before them, base62
/// with the `0-9A-Za-z` alphabet. Computed here rather than borrowed from the
/// scanner, so a benchmark that stopped finding anything would show up as a
/// failed expectation instead of a suspiciously fast scan.
fn synthetic_github_token() -> String {
    const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut crc = !0u32;
    for &byte in SYNTHETIC_GITHUB_BODY.as_bytes() {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    let mut remaining = !crc;
    let mut checksum = [b'0'; 6];
    for slot in checksum.iter_mut().rev() {
        *slot = ALPHABET[(remaining % 62) as usize];
        remaining /= 62;
    }
    let checksum = std::str::from_utf8(&checksum).expect("base62 output is ASCII");
    format!("ghp_{SYNTHETIC_GITHUB_BODY}{checksum}")
}

#[derive(Clone, Copy)]
enum Expectation {
    Clean,
    Matches,
}

struct Corpus {
    name: &'static str,
    text: String,
    lines: usize,
    expectation: Expectation,
    warmups: usize,
    measured: usize,
}

impl Corpus {
    fn new(
        name: &'static str,
        text: String,
        expectation: Expectation,
        warmups: usize,
        measured: usize,
    ) -> Self {
        let lines = text.lines().count();
        Self {
            name,
            text,
            lines,
            expectation,
            warmups,
            measured,
        }
    }
}

struct Measurement {
    name: &'static str,
    lines: usize,
    bytes: usize,
    median: Duration,
    minimum: Duration,
    nanoseconds_per_line: f64,
    mebibytes_per_second: f64,
}

struct ConfigMeasurement {
    median: Duration,
    minimum: Duration,
}

struct ConfigFixture {
    path: PathBuf,
    previous_dir: Option<OsString>,
}

impl ConfigFixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("redact-scan-cost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create benchmark config directory");
        std::fs::write(path.join("config.json"), BENCH_CONFIG)
            .expect("write benchmark configuration");
        let previous_dir = std::env::var_os("HERDR_PLUGIN_CONFIG_DIR");
        std::env::set_var("HERDR_PLUGIN_CONFIG_DIR", &path);
        Self { path, previous_dir }
    }
}

impl Drop for ConfigFixture {
    fn drop(&mut self) {
        if let Some(previous_dir) = &self.previous_dir {
            std::env::set_var("HERDR_PLUGIN_CONFIG_DIR", previous_dir);
        } else {
            std::env::remove_var("HERDR_PLUGIN_CONFIG_DIR");
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A fixed-seed linear congruential generator keeps every generated byte stable
/// without adding an RNG dependency to a crate whose dependency tree is small
/// on purpose. Randomness quality is irrelevant; variation in pane-like text is
/// all this generator supplies.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

fn append_pane_line(text: &mut String, line: usize, generator: &mut Lcg) {
    let first = generator.next();
    let second = generator.next();
    let minute = first % 60;
    let second_of_minute = second % 60;
    let millis = (first >> 16) % 1000;
    let pane = (second >> 20) % 64;
    let step = (first >> 28) % 800;
    let elapsed = (second >> 36) % 900;

    let result = match line % 6 {
        0 => writeln!(
            text,
            "2026-08-22T14:{minute:02}:{second_of_minute:02}.{millis:03}Z INFO pane={pane:02} step={step:03} path=/workspace/src/task_{:03}.rs elapsed={elapsed}ms",
            first % 240,
        ),
        1 => writeln!(
            text,
            "agent@pane-{pane:02}:/workspace/project$ cargo check -p crate_{:02} --target-dir /tmp/build-{:08x}",
            first % 40,
            second as u32,
        ),
        2 => writeln!(
            text,
            "{{\"level\":\"debug\",\"pane\":\"p-{pane:02}\",\"event\":\"tool_result\",\"bytes\":{},\"id\":\"{:012x}\"}}",
            512 + first % 65_024,
            second & 0xffff_ffff_ffff,
        ),
        3 => writeln!(
            text,
            "Resolved module_{:03} from /home/runner/work/redact/src/component_{:03}.rs after {elapsed}ms.",
            first % 300,
            second % 300,
        ),
        4 => writeln!(
            text,
            "[2026-08-22 14:{minute:02}:{second_of_minute:02}] WARN retry={} status=503 request_id={:016x} worker=pane-{pane:02}",
            1 + first % 5,
            second,
        ),
        _ => writeln!(
            text,
            "diff --git a/src/unit_{:03}.rs b/src/unit_{:03}.rs index {:07x}..{:07x} 100644",
            first % 180,
            first % 180,
            first as u32 & 0x0fff_ffff,
            second as u32 & 0x0fff_ffff,
        ),
    };
    if let Err(error) = result {
        panic!("could not append generated pane text to an in-memory String: {error}");
    }
}

fn clean_pane(lines: usize, seed: u64) -> String {
    let mut text = String::with_capacity(lines * 96);
    let mut generator = Lcg(seed);
    for line in 0..lines {
        append_pane_line(&mut text, line, &mut generator);
    }
    text
}

fn sparse_pane(lines: usize, seed: u64) -> String {
    let mut text = String::with_capacity(lines * 96);
    let mut generator = Lcg(seed);
    let token = synthetic_github_token();
    for line in 0..lines {
        if (line + 1).is_multiple_of(500) {
            // This is the provider's documented EXAMPLE-shaped token style,
            // never a credential copied from an environment or account.
            let result = writeln!(
                text,
                "agent@pane-{:02}:/workspace/project$ export GITHUB_TOKEN={token}",
                generator.next() % 64,
            );
            if let Err(error) = result {
                panic!("could not append a synthetic sparse match to an in-memory String: {error}");
            }
        } else {
            append_pane_line(&mut text, line, &mut generator);
        }
    }
    text
}

fn matchy_pane(lines: usize, seed: u64) -> String {
    let mut text = String::with_capacity(lines * 72);
    let mut generator = Lcg(seed);
    for line in 0..lines {
        if line % 5 == 4 {
            append_pane_line(&mut text, line, &mut generator);
            continue;
        }
        let sequence = generator.next();
        // The `bench_` prefix makes these values visibly generated rather than
        // issued, while their mixed suffix still exercises the weak candidate
        // path and its per-rule ceiling.
        let result = writeln!(text, "FOO_TOKEN=bench_{line:08}_{sequence:016x}_A1B2C3D4");
        if let Err(error) = result {
            panic!("could not append a synthetic weak candidate to an in-memory String: {error}");
        }
    }
    text
}

fn one_megabyte_line(seed: u64) -> String {
    let token = synthetic_github_token();
    let body_bytes = ONE_MIB - token.len() - 1;
    let mut text = String::with_capacity(ONE_MIB);
    let mut generator = Lcg(seed);
    text.push_str("| ");
    while text.len() < body_bytes {
        let result = write!(text, "{:016x}", generator.next());
        if let Err(error) = result {
            panic!(
                "could not append the one-megabyte synthetic line to an in-memory String: {error}"
            );
        }
    }
    text.truncate(body_bytes);
    text.push(' ');
    text.push_str(&token);
    text
}

fn corpora() -> Vec<Corpus> {
    vec![
        Corpus::new(
            "clean_400",
            clean_pane(400, 0x4000_5eed),
            Expectation::Clean,
            3,
            11,
        ),
        Corpus::new(
            "clean_5k",
            clean_pane(5_000, 0x5000_5eed),
            Expectation::Clean,
            3,
            9,
        ),
        Corpus::new(
            "clean_20k",
            clean_pane(20_000, 0x2000_05ee_d123_4567),
            Expectation::Clean,
            2,
            7,
        ),
        Corpus::new(
            "sparse_20k",
            sparse_pane(20_000, 0x5a25_e200_05ee_d123),
            Expectation::Matches,
            2,
            7,
        ),
        Corpus::new(
            "matchy_5k",
            matchy_pane(5_000, 0x5ca1_ab1e_5eed),
            Expectation::Matches,
            2,
            7,
        ),
        Corpus::new(
            "one_megabyte_line",
            one_megabyte_line(0x104d_1b1e_5eed),
            Expectation::Matches,
            2,
            7,
        ),
    ]
}

fn verify(corpus: &Corpus, match_count: usize) {
    match corpus.expectation {
        Expectation::Clean if match_count != 0 => panic!(
            "benchmark corpus `{}` was expected to be clean but produced {match_count} matches; timing it would measure the wrong workload",
            corpus.name,
        ),
        Expectation::Matches if match_count == 0 => panic!(
            "benchmark corpus `{}` was expected to exercise matching but produced no matches; timing it would measure only rejection",
            corpus.name,
        ),
        Expectation::Clean | Expectation::Matches => {}
    }
}

fn measure(corpus: &Corpus, rules: &Rules) -> Measurement {
    if corpus.measured == 0 {
        panic!(
            "benchmark corpus `{}` configured zero measured iterations",
            corpus.name
        );
    }

    for _ in 0..corpus.warmups {
        drop(black_box(scan(
            black_box(corpus.text.as_str()),
            rules,
            &KEY,
        )));
    }

    let mut elapsed = Vec::with_capacity(corpus.measured);
    for _ in 0..corpus.measured {
        let started = Instant::now();
        let matches = scan(black_box(corpus.text.as_str()), rules, &KEY);
        let duration = started.elapsed();
        black_box(matches);
        elapsed.push(duration);
    }
    elapsed.sort_unstable();

    let minimum = elapsed[0];
    let median = elapsed[elapsed.len() / 2];
    if median.is_zero() {
        panic!(
            "benchmark timer reported a zero median for `{}`; this clock cannot measure the workload",
            corpus.name
        );
    }
    let nanoseconds_per_line = median.as_nanos() as f64 / corpus.lines as f64;
    let mebibytes_per_second = corpus.text.len() as f64 / ONE_MIB as f64 / median.as_secs_f64();

    Measurement {
        name: corpus.name,
        lines: corpus.lines,
        bytes: corpus.text.len(),
        median,
        minimum,
        nanoseconds_per_line,
        mebibytes_per_second,
    }
}

fn load_and_compile() -> Rules {
    let config = config::load().expect("load benchmark configuration");
    Rules::compile(&config).expect("compile benchmark rules")
}

fn measure_config_compile() -> ConfigMeasurement {
    for _ in 0..CONFIG_WARMUPS {
        drop(black_box(load_and_compile()));
    }

    let mut elapsed = Vec::with_capacity(CONFIG_MEASURED);
    for _ in 0..CONFIG_MEASURED {
        let started = Instant::now();
        let rules = load_and_compile();
        let duration = started.elapsed();
        black_box(rules);
        elapsed.push(duration);
    }
    elapsed.sort_unstable();

    ConfigMeasurement {
        median: elapsed[elapsed.len() / 2],
        minimum: elapsed[0],
    }
}

fn elapsed(duration: Duration) -> String {
    if duration >= Duration::from_secs(1) {
        format!("{:.3} s", duration.as_secs_f64())
    } else if duration >= Duration::from_millis(1) {
        format!("{:.3} ms", duration.as_secs_f64() * 1_000.0)
    } else {
        format!("{:.3} us", duration.as_secs_f64() * 1_000_000.0)
    }
}

fn report(measurements: &[Measurement], config_compile: &ConfigMeasurement) {
    println!(
        "{:<20} {:>8} {:>10} {:>12} {:>12} {:>14} {:>12}",
        "corpus", "lines", "bytes", "median", "minimum", "ns/line", "MiB/s"
    );
    println!("{}", "-".repeat(94));
    for measurement in measurements {
        println!(
            "{:<20} {:>8} {:>10} {:>12} {:>12} {:>14.0} {:>12.2}",
            measurement.name,
            measurement.lines,
            measurement.bytes,
            elapsed(measurement.median),
            elapsed(measurement.minimum),
            measurement.nanoseconds_per_line,
            measurement.mebibytes_per_second,
        );
    }

    let Some(largest) = measurements
        .iter()
        .find(|measurement| measurement.name == "clean_20k")
    else {
        panic!("the benchmark report is missing its headline `clean_20k` measurement");
    };
    let budget_share = largest.median.as_secs_f64() / MINIMUM_CYCLE_BUDGET.as_secs_f64() * 100.0;
    println!();
    println!(
        "Largest configurable buffer: clean_20k scans {} lines ({} bytes) in a median {}, at {:.2} MiB/s.",
        largest.lines,
        largest.bytes,
        elapsed(largest.median),
        largest.mebibytes_per_second,
    );
    println!(
        "Cycle reading budget: that scan is {budget_share:.3}% of the 30 s minimum; the budget is dominated by one socket round trip per pane, not by scanning."
    );
    let minimum_interval = Duration::from_secs(MIN_INTERVAL_SECONDS);
    let interval_share =
        config_compile.median.as_secs_f64() / minimum_interval.as_secs_f64() * 100.0;
    println!();
    println!(
        "Config load + rule compile: median {}, minimum {} ({interval_share:.3}% of the {} s minimum scan interval).",
        elapsed(config_compile.median),
        elapsed(config_compile.minimum),
        minimum_interval.as_secs(),
    );
}

fn main() {
    // The harness-less test convention is a forwarded `--test` argument. The
    // debug-assertions fallback covers Cargo releases that instead compile this
    // target in the test profile; `cargo bench` always uses the optimized one.
    let test_mode = cfg!(debug_assertions) || std::env::args().any(|argument| argument == "--test");
    let _config_fixture = ConfigFixture::new();
    let rules = Rules::builtin();
    let corpora = corpora();

    if test_mode {
        for corpus in &corpora {
            let matches = scan(black_box(corpus.text.as_str()), &rules, &KEY);
            verify(corpus, matches.len());
            black_box(matches);
        }
        drop(load_and_compile());
        println!("scan_cost benchmark corpora verified");
        return;
    }

    for corpus in &corpora {
        let matches = scan(corpus.text.as_str(), &rules, &KEY);
        verify(corpus, matches.len());
    }
    let measurements: Vec<Measurement> = corpora
        .iter()
        .map(|corpus| measure(corpus, &rules))
        .collect();
    let config_compile = measure_config_compile();
    report(&measurements, &config_compile);
}
