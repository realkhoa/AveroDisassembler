//! Generic, format-agnostic heuristics over extracted strings and whole-file entropy.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::json;

use crate::analyzers::{AnalysisContext, Analyzer, Fragment};
use crate::evidence::{loc, make_evidence};
use crate::findings::make_finding;
use crate::ir::{Artifact, Kind, Severity};

const ENGINE: &str = "avero.heuristics";

fn url_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)(?:https?|ftp)://[^\s'"<>]{4,2048}"#).expect("url regex"))
}

fn domain_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|vn|ru|cn|xyz|top|info|biz|onion)\b")
            .expect("domain regex")
    })
}

fn ipv4_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
            .expect("ipv4 regex")
    })
}

fn command_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(-enc(?:odedcommand)?\s|powershell(?:\.exe)?\s+-|cmd\.exe\s+/c|bitsadmin|certutil\s+-urlcache|mshta\s|regsvr32\s+/s|rundll32\s|wmic\s+process\s+call\s+create|schtasks\s+/create)",
        )
        .expect("command regex")
    })
}

fn base64_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[A-Za-z0-9+/]{80,}={0,2}\b").expect("base64 regex"))
}

fn is_noise_ip(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return true;
    }
    let first: u32 = parts[0].parse().unwrap_or(0);
    let last: u32 = parts[3].parse().unwrap_or(0);
    last == 0 || first == 0 || first == 127 || first == 255 || last == 255
}

pub struct HeuristicsAnalyzer;

impl Analyzer for HeuristicsAnalyzer {
    fn id(&self) -> &'static str {
        "heuristics.generic"
    }

    fn accepts(&self, _artifact: &Artifact) -> bool {
        true
    }

    fn priority(&self) -> i32 {
        30
    }

    fn requires(&self) -> &'static [&'static str] {
        &["strings.generic"]
    }

    fn run(&self, _ctx: &AnalysisContext, artifact: &Artifact) -> Fragment {
        let mut fragment = Fragment::default();
        let mut urls: BTreeSet<String> = BTreeSet::new();
        let mut domains: BTreeSet<String> = BTreeSet::new();
        let mut ips: BTreeSet<String> = BTreeSet::new();
        let mut suspicious: Vec<String> = Vec::new();
        let mut base64_count = 0usize;

        for entry in &artifact.strings {
            for matched in url_regex().find_iter(&entry.value) {
                urls.insert(matched.as_str().to_string());
            }
            for matched in domain_regex().find_iter(&entry.value) {
                domains.insert(matched.as_str().to_ascii_lowercase());
            }
            for matched in ipv4_regex().find_iter(&entry.value) {
                if !is_noise_ip(matched.as_str()) {
                    ips.insert(matched.as_str().to_string());
                }
            }
            if command_regex().is_match(&entry.value) && suspicious.len() < 10 {
                suspicious.push(entry.value.chars().take(180).collect());
            }
            base64_count += base64_regex().find_iter(&entry.value).count();
        }
        // version-like domains are not interesting; drop obvious file names
        domains.retain(|domain| !domain.ends_with(".dll") && !domain.ends_with(".exe"));
        let urls: Vec<String> = urls.into_iter().take(25).collect();
        let domains: Vec<String> = domains.into_iter().take(25).collect();
        let ips: Vec<String> = ips.into_iter().take(25).collect();

        fragment.facts.insert("urls".into(), json!(urls));
        fragment.facts.insert("domains".into(), json!(domains));
        fragment.facts.insert("ipv4".into(), json!(ips));
        fragment
            .facts
            .insert("suspicious_command_strings".into(), json!(suspicious));
        fragment
            .facts
            .insert("base64_blob_count".into(), json!(base64_count));

        if !urls.is_empty() {
            let evidence = make_evidence(
                ENGINE,
                env!("CARGO_PKG_VERSION"),
                "string",
                loc(vec![("count", json!(urls.len()))]),
                Some(urls.iter().take(8).cloned().collect::<Vec<_>>().join("; ")),
                0.9,
                Vec::new(),
            );
            fragment.findings.push(make_finding(
                Severity::Low,
                "network",
                format!("URL strings in binary ({})", urls.len()),
                "URLs may be C2 endpoints, update servers or documentation. Check cross-reference context before concluding."
                    .to_string(),
                &[&evidence],
                0.6,
                None,
            ));
            fragment.evidence.push(evidence);
        }
        if !ips.is_empty() {
            let evidence = make_evidence(
                ENGINE,
                env!("CARGO_PKG_VERSION"),
                "string",
                loc(vec![("count", json!(ips.len()))]),
                Some(ips.iter().take(8).cloned().collect::<Vec<_>>().join("; ")),
                0.85,
                Vec::new(),
            );
            fragment.findings.push(make_finding(
                Severity::Medium,
                "network",
                format!("Hardcoded IPv4 addresses ({})", ips.len()),
                "Hardcoded IPs in a binary are often C2/backend infrastructure. Verify via cross-reference."
                    .to_string(),
                &[&evidence],
                0.6,
                None,
            ));
            fragment.evidence.push(evidence);
        }
        if !suspicious.is_empty() {
            let evidence = make_evidence(
                ENGINE,
                env!("CARGO_PKG_VERSION"),
                "string",
                loc(vec![("count", json!(suspicious.len()))]),
                Some(
                    suspicious
                        .iter()
                        .take(5)
                        .map(|value| value.chars().take(120).collect::<String>())
                        .collect::<Vec<_>>()
                        .join("; "),
                ),
                0.8,
                Vec::new(),
            );
            fragment.findings.push(make_finding(
                Severity::High,
                "execution",
                "Suspicious execution command strings",
                "Found shell/command execution patterns (PowerShell -enc, cmd /c, mshta, certutil, ...). \
                 This is a strong signal of a loader/dropper or malicious script, but can also be a legitimate installer."
                    .to_string(),
                &[&evidence],
                0.65,
                None,
            ));
            fragment.evidence.push(evidence);
        }
        if base64_count >= 5 {
            let evidence = make_evidence(
                ENGINE,
                env!("CARGO_PKG_VERSION"),
                "heuristic",
                loc(vec![("count", json!(base64_count))]),
                Some(format!("{base64_count} base64-like blobs")),
                0.6,
                Vec::new(),
            );
            fragment.findings.push(make_finding(
                Severity::Low,
                "encoding",
                format!("Many base64-like blobs ({base64_count})"),
                "Long strings consisting only of base64 characters — may be an encrypted payload or configuration data."
                    .to_string(),
                &[&evidence],
                0.45,
                None,
            ));
            fragment.evidence.push(evidence);
        }
        if artifact.kinds.len() == 1 && artifact.kinds[0] == Kind::Unknown {
            fragment
                .unknowns
                .push("could not identify the format — only raw triage available".to_string());
        }
        if artifact.size == 0 {
            fragment.warnings.push("empty file (0 bytes)".to_string());
        }
        if artifact.entropy >= 7.5 && artifact.size >= 64 * 1024 {
            let evidence = make_evidence(
                ENGINE,
                env!("CARGO_PKG_VERSION"),
                "heuristic",
                loc(vec![
                    ("entropy", json!(artifact.entropy)),
                    ("size", json!(artifact.size)),
                ]),
                Some(format!(
                    "whole-file entropy {:.3} over {} bytes",
                    artifact.entropy, artifact.size
                )),
                0.8,
                vec!["high entropy may be due to legitimate compressed/asset data".to_string()],
            );
            fragment.findings.push(make_finding(
                Severity::Low,
                "packing",
                "Whole-file entropy is very high",
                "Entropy near 8 bits/byte across the whole file is common in compressed/encrypted files or packers. \
                 Check the specific sections/format before concluding."
                    .to_string(),
                &[&evidence],
                0.5,
                None,
            ));
            fragment.evidence.push(evidence);
        }
        fragment
    }
}
