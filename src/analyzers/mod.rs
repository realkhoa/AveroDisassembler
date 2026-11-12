//! Analyzer protocol and built-in analyzer registry.
//!
//! Analyzers are small, independent units. They never print and never render; they return
//! a [`Fragment`] that the pipeline merges into the artifact and the report.

pub mod apk;
pub mod dotnet;
pub mod elf;
pub mod heuristics;
pub mod il2cpp;
pub mod macho;
pub mod pe;
pub mod signatures_analyzer;
pub mod strings_analyzer;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ir::{Artifact, Evidence, Export, Finding, Import, Section, StringEntry, TOOL_VERSION};

/// Read-only context handed to every analyzer. `data` is the whole artifact in memory.
pub struct AnalysisContext<'a> {
    pub data: &'a [u8],
    pub min_string_len: usize,
    pub max_strings: usize,
    pub max_scan_bytes: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fragment {
    #[serde(default)]
    pub facts: BTreeMap<String, Value>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub imports: Vec<Import>,
    #[serde(default)]
    pub exports: Vec<Export>,
    #[serde(default)]
    pub strings: Vec<StringEntry>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default)]
    pub unknowns: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

pub trait Analyzer {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str {
        TOOL_VERSION
    }
    fn accepts(&self, artifact: &Artifact) -> bool;
    fn priority(&self) -> i32 {
        100
    }
    fn requires(&self) -> &'static [&'static str] {
        &[]
    }
    fn run(&self, ctx: &AnalysisContext, artifact: &Artifact) -> Fragment;
}

pub fn builtin_analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![
        Box::new(pe::PeAnalyzer),
        Box::new(elf::ElfAnalyzer),
        Box::new(macho::MachOAnalyzer),
        Box::new(dotnet::DotnetAnalyzer),
        Box::new(apk::ApkAnalyzer),
        Box::new(il2cpp::Il2CppAnalyzer),
        Box::new(strings_analyzer::StringsAnalyzer),
        Box::new(signatures_analyzer::SignaturesAnalyzer),
        Box::new(heuristics::HeuristicsAnalyzer),
    ]
}
