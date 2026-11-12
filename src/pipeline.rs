//! Analysis pipeline: select analyzers, respect dependencies, merge fragments, cache.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::analyzers::{builtin_analyzers, AnalysisContext, Analyzer};
use crate::hashing::digest;
use crate::ir::{Artifact, Evidence, Report, Severity};
use crate::util::sha1_hex;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub min_string_len: usize,
    pub max_strings: usize,
    pub max_scan_bytes: usize,
    pub use_cache: bool,
    pub cache_dir: PathBuf,
    pub enabled: Option<HashSet<String>>,
    pub disabled: HashSet<String>,
    pub jobs: usize,
    pub verbose: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            min_string_len: 6,
            max_strings: 50_000,
            max_scan_bytes: 64 * 1024 * 1024,
            use_cache: true,
            cache_dir: std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".avero")
                .join("cache"),
            enabled: None,
            disabled: HashSet::new(),
            jobs: 4,
            verbose: false,
        }
    }
}

impl ScanOptions {
    fn fingerprint(&self) -> String {
        sha1_hex(
            format!(
                "{}|{}|{}",
                self.min_string_len, self.max_strings, self.max_scan_bytes
            )
            .as_bytes(),
        )
    }
}

fn schedule(analyzers: &[Box<dyn Analyzer>]) -> Vec<usize> {
    let mut done: HashSet<String> = HashSet::new();
    let mut order = Vec::new();
    let mut remaining: Vec<usize> = (0..analyzers.len()).collect();
    while !remaining.is_empty() {
        let mut progressed = false;
        let mut still_waiting = Vec::new();
        for index in remaining {
            let analyzer = &analyzers[index];
            if analyzer
                .requires()
                .iter()
                .all(|required| done.contains(*required))
            {
                order.push(index);
                done.insert(analyzer.id().to_string());
                progressed = true;
            } else {
                still_waiting.push(index);
            }
        }
        if !progressed {
            order.extend(still_waiting);
            break;
        }
        remaining = still_waiting;
    }
    order
}

/// Run the pipeline. Analyzer failures are surfaced as warnings, never as a hard error.
pub fn analyze(artifact: &mut Artifact, data: &[u8], options: &ScanOptions) -> Report {
    let mut analyzers = builtin_analyzers();
    analyzers.retain(|analyzer| {
        if !analyzer.accepts(artifact) {
            return false;
        }
        if let Some(enabled) = &options.enabled {
            if !enabled.contains(analyzer.id()) {
                return false;
            }
        }
        if options.disabled.contains(analyzer.id()) {
            return false;
        }
        true
    });
    analyzers.sort_by_key(|analyzer| (analyzer.priority(), analyzer.id()));

    let fingerprint = options.fingerprint();
    let mut report = Report::new(artifact.clone());
    let mut merged_evidence: Vec<Evidence> = artifact.evidence.clone();

    for index in schedule(&analyzers) {
        let analyzer = &analyzers[index];
        let cache_key = sha1_hex(
            format!(
                "{}|{}|{}|{}",
                analyzer.id(),
                analyzer.version(),
                artifact.id,
                fingerprint
            )
            .as_bytes(),
        );
        let cache_path = options.cache_dir.join(format!("{cache_key}.json"));
        let mut cached = false;
        let fragment = if options.use_cache && cache_path.is_file() {
            match std::fs::read(&cache_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<crate::analyzers::Fragment>(&bytes).ok())
            {
                Some(fragment) => {
                    cached = true;
                    fragment
                }
                None => {
                    let context = AnalysisContext {
                        data,
                        min_string_len: options.min_string_len,
                        max_strings: options.max_strings,
                        max_scan_bytes: options.max_scan_bytes,
                    };
                    analyzer.run(&context, artifact)
                }
            }
        } else {
            let context = AnalysisContext {
                data,
                min_string_len: options.min_string_len,
                max_strings: options.max_strings,
                max_scan_bytes: options.max_scan_bytes,
            };
            analyzer.run(&context, artifact)
        };
        if options.use_cache && !cached {
            let _ = std::fs::create_dir_all(&options.cache_dir);
            if let Ok(serialized) = serde_json::to_vec(&fragment) {
                let _ = std::fs::write(&cache_path, serialized);
            }
        }

        report.coverage.insert(
            analyzer.id().to_string(),
            if cached { "ok (cached)" } else { "ok" }.to_string(),
        );
        if options.verbose {
            eprintln!(
                "  {:<28} {:<12} {} facts",
                analyzer.id(),
                if cached { "ok (cached)" } else { "ok" },
                fragment.facts.len()
            );
        }

        artifact.sections.extend(fragment.sections);
        artifact.imports.extend(fragment.imports);
        artifact.exports.extend(fragment.exports);
        artifact.strings.extend(fragment.strings);
        for (key, value) in fragment.metadata {
            artifact.metadata.entry(key).or_insert(value);
        }
        merged_evidence.extend(fragment.evidence.clone());
        if !fragment.facts.is_empty() {
            report.facts.insert(
                analyzer.id().to_string(),
                Value::Object(fragment.facts.into_iter().collect()),
            );
        }
        report.findings.extend(fragment.findings);
        report.unknowns.extend(
            fragment
                .unknowns
                .into_iter()
                .map(|item| format!("[{}] {item}", analyzer.id())),
        );
        report.warnings.extend(
            fragment
                .warnings
                .into_iter()
                .map(|item| format!("[{}] {item}", analyzer.id())),
        );
    }

    // de-duplicate evidence by ID, preserving first occurrence
    let mut seen: HashSet<String> = HashSet::new();
    for evidence in merged_evidence {
        if seen.insert(evidence.id.clone()) {
            artifact.evidence.push(evidence);
        }
    }
    report.artifact = artifact.clone();
    report.findings.sort_by(|left, right| {
        right
            .severity
            .rank()
            .cmp(&left.severity.rank())
            .then_with(|| left.id.cmp(&right.id))
    });
    report
}

/// Convenience for tools/tests: probe + analyze an in-memory buffer.
pub fn scan_bytes(data: &[u8], path: Option<&Path>, options: &ScanOptions) -> Report {
    let mut artifact = crate::probe::probe_bytes(data, path);
    analyze(&mut artifact, data, options)
}

/// Cache invalidation helper used by tests and dev loops.
pub fn cache_key(analyzer: &dyn Analyzer, artifact: &Artifact, options: &ScanOptions) -> String {
    sha1_hex(
        format!(
            "{}|{}|{}|{}",
            analyzer.id(),
            analyzer.version(),
            artifact.id,
            options.fingerprint()
        )
        .as_bytes(),
    )
}

/// Deterministic artifact ID helper for tests.
pub fn artifact_id(data: &[u8]) -> String {
    digest(data).sha256
}

/// Aggregated severity counts for the summary renderer.
pub fn severity_counts(report: &Report) -> BTreeMap<&'static str, usize> {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        counts.insert(severity.as_str(), 0);
    }
    for finding in &report.findings {
        *counts.entry(finding.severity.as_str()).or_default() += 1;
    }
    counts
}
