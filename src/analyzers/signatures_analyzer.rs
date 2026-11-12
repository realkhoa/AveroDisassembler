//! Signature analyzer: runs the embedded YARA-subset ruleset against the artifact bytes.

use serde_json::json;

use crate::analyzers::{AnalysisContext, Analyzer, Fragment};
use crate::evidence::{loc, make_evidence};
use crate::findings::make_finding;
use crate::ir::{Artifact, Severity};
use crate::signatures;

const ENGINE: &str = "avero.signatures";

pub struct SignaturesAnalyzer;

impl Analyzer for SignaturesAnalyzer {
    fn id(&self) -> &'static str {
        "signatures.rules"
    }

    fn accepts(&self, _artifact: &Artifact) -> bool {
        true
    }

    fn priority(&self) -> i32 {
        25
    }

    fn run(&self, ctx: &AnalysisContext, _artifact: &Artifact) -> Fragment {
        let mut fragment = Fragment::default();
        let ruleset = match signatures::default_ruleset() {
            Ok(ruleset) => ruleset,
            Err(error) => {
                fragment
                    .warnings
                    .push(format!("signatures.rules: ruleset compile error: {error}"));
                return fragment;
            }
        };
        let matches = ruleset.scan(ctx.data);
        if matches.is_empty() {
            fragment
                .facts
                .insert("matched_rules".into(), json!(Vec::<String>::new()));
            return fragment;
        }
        let mut matched_names = Vec::new();
        let mut match_facts = Vec::new();
        for rule_match in matches {
            let rule = &ruleset.rules[rule_match.rule_index];
            matched_names.push(rule.name.clone());
            let first_offset = rule_match
                .first_offset
                .map(|offset| format!("0x{offset:x}"))
                .unwrap_or_else(|| "?".to_string());
            let evidence = make_evidence(
                ENGINE,
                env!("CARGO_PKG_VERSION"),
                "rule",
                loc(vec![
                    ("rule", json!(rule.name)),
                    ("matched_patterns", json!(rule_match.matched_patterns)),
                    ("first_offset", json!(first_offset)),
                ]),
                Some(format!(
                    "{}: {}/{} patterns matched, first offset {}",
                    rule.name,
                    rule_match.matched_patterns,
                    rule.patterns.len(),
                    first_offset
                )),
                0.7,
                vec!["signature heuristic: verify context before concluding".to_string()],
            );
            let detail = if rule.description.is_empty() {
                format!(
                    "Rule `{}` matched {}/{} patterns, first offset {}.",
                    rule.name,
                    rule_match.matched_patterns,
                    rule.patterns.len(),
                    first_offset
                )
            } else {
                format!(
                    "{} (matched {}/{} patterns, first offset {}).",
                    rule.description,
                    rule_match.matched_patterns,
                    rule.patterns.len(),
                    first_offset
                )
            };
            fragment.findings.push(make_finding(
                rule.severity,
                &rule.category,
                format!("Signature: {}", rule.name),
                detail,
                &[&evidence],
                0.7,
                None,
            ));
            fragment.evidence.push(evidence);
            match_facts.push(json!({
                "rule": rule.name,
                "matched_patterns": rule_match.matched_patterns,
                "total_patterns": rule.patterns.len(),
                "first_offset": first_offset,
                "severity": rule.severity.as_str(),
            }));
        }
        fragment
            .facts
            .insert("matched_rules".into(), json!(matched_names));
        fragment.facts.insert("matches".into(), json!(match_facts));
        let _ = Severity::Info;
        fragment
    }
}
