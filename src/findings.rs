//! Deterministic findings.

use crate::ir::{Evidence, Finding, Severity};
use crate::util::sha1_hex;

/// Build a finding. The ID is content-addressed (category + title + evidence IDs).
pub fn make_finding(
    severity: Severity,
    category: &str,
    title: impl Into<String>,
    detail: impl Into<String>,
    evidence: &[&Evidence],
    confidence: f64,
    remediation: Option<String>,
) -> Finding {
    let title = title.into();
    let detail = detail.into();
    let mut ids: Vec<String> = evidence.iter().map(|item| item.id.clone()).collect();
    ids.sort();
    let seed = format!("{}|{}|{}", category, title, ids.join("|"));
    Finding {
        id: format!("F-{}", &sha1_hex(seed.as_bytes())[..12]),
        severity,
        category: category.to_string(),
        title,
        detail,
        evidence_ids: ids,
        confidence,
        remediation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{loc, make_evidence};
    use serde_json::json;

    #[test]
    fn finding_ids_are_deterministic_and_reference_evidence() {
        let ev = make_evidence(
            "test",
            "1.0",
            "section",
            loc(vec![("name", json!(".text"))]),
            None,
            1.0,
            vec![],
        );
        let first = make_finding(
            Severity::Medium,
            "packing",
            "High entropy",
            "detail",
            &[&ev],
            0.5,
            None,
        );
        let second = make_finding(
            Severity::Medium,
            "packing",
            "High entropy",
            "detail",
            &[&ev],
            0.5,
            None,
        );
        assert_eq!(first.id, second.id);
        assert_eq!(first.evidence_ids, vec![ev.id]);
    }
}
