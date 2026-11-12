//! Avero core library — fast, evidence-first reverse engineering workbench.

pub mod analyzers;
pub mod axml;
pub mod engine;
pub mod evidence;
pub mod findings;
pub mod hashing;
pub mod ir;
pub mod pehdr;
pub mod pipeline;
pub mod probe;
pub mod report;
pub mod server;
pub mod signatures;
pub mod strings;
pub mod util;
pub mod zipscan;

pub use ir::{Artifact, Kind, Report, Severity};
