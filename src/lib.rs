//! redact — credential warnings for herdr agent panes.
//!
//! Agents `cat .env`, echo tokens into logs, and print curl commands with bearer
//! headers. Repository scanners do not help, because the exposure surface is the
//! terminal, which nothing watches. This plugin watches it, and tells you before
//! you screenshot, stream, or paste it.
//!
//! The crate is split into a library plus a thin binary so that the integration
//! tests in `tests/` can reach the real modules.
//!
//! # Where a secret is allowed to exist
//!
//! Only inside [`scan`], and only for the duration of one call to
//! [`scan::scan`]. Every type that crosses a module boundary lives in [`model`]
//! and carries a masked preview, a length and a keyed digest instead of a value.
//! That is the whole safety argument, and `tests/never_leaks.rs` is the proof.

pub mod config;
pub mod daemon;
pub mod findings;
pub mod herdr;
pub mod model;
pub mod render;
pub mod scan;
pub mod setup;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
