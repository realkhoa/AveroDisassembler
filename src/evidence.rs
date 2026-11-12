//! Deterministic evidence helpers.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::ir::{Evidence, Producer};
use crate::util::sha1_hex;

pub const MAX_EXCERPT: usize = 512;

/// Build a locator map from pairs (order-independent because it becomes a BTreeMap).
pub fn loc(pairs: Vec<(&str, Value)>) -> BTreeMap<String, Value> {
    pairs
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
}

/// Build evidence whose ID is content-addressed, so re-runs produce identical reports.
pub fn make_evidence(
    engine: &str,
    version: &str,
    kind: &str,
    locator: BTreeMap<String, Value>,
    excerpt: Option<String>,
    confidence: f64,
    limitations: Vec<String>,
) -> Evidence {
    let excerpt = excerpt.map(|mut text| {
        if text.chars().count() > MAX_EXCERPT {
            text = text.chars().take(MAX_EXCERPT - 3).collect::<String>() + "...";
        }
        text
    });
    let locator_json = serde_json::to_string(&locator).unwrap_or_default();
    let seed = format!(
        "{}|{}|{}|{}|{}",
        engine,
        version,
        kind,
        locator_json,
        excerpt.clone().unwrap_or_default()
    );
    Evidence {
        id: sha1_hex(seed.as_bytes())[..16].to_string(),
        producer: Producer {
            engine: engine.to_string(),
            version: version.to_string(),
            command: None,
        },
        kind: kind.to_string(),
        locator,
        excerpt,
        confidence,
        limitations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn evidence_ids_are_deterministic() {
        let make = || {
            make_evidence(
                "test",
                "1.0",
                "header",
                loc(vec![("offset", json!(0))]),
                Some("hello".into()),
                1.0,
                vec![],
            )
        };
        assert_eq!(make().id, make().id);
        assert_ne!(
            make().id,
            make_evidence(
                "test",
                "1.0",
                "header",
                loc(vec![("offset", json!(1))]),
                Some("hello".into()),
                1.0,
                vec![]
            )
            .id
        );
    }

    #[test]
    fn excerpt_is_truncated() {
        let evidence = make_evidence(
            "test",
            "1.0",
            "string",
            BTreeMap::new(),
            Some("x".repeat(2000)),
            0.5,
            vec![],
        );
        assert!(evidence.excerpt.unwrap().chars().count() <= MAX_EXCERPT);
    }
}
