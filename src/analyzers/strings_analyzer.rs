//! Strings analyzer: ASCII + UTF-16LE extraction with section mapping.

use serde_json::json;

use crate::analyzers::{AnalysisContext, Analyzer, Fragment};
use crate::ir::{Artifact, StringEntry};
use crate::strings::{extract_ascii, extract_utf16le, section_for_offset};

const DEFAULT_MAX_SCAN: usize = 64 * 1024 * 1024;

pub struct StringsAnalyzer;

impl Analyzer for StringsAnalyzer {
    fn id(&self) -> &'static str {
        "strings.generic"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn accepts(&self, _artifact: &Artifact) -> bool {
        true
    }

    fn priority(&self) -> i32 {
        20
    }

    fn run(&self, ctx: &AnalysisContext, artifact: &Artifact) -> Fragment {
        let mut fragment = Fragment::default();
        let scan_len = ctx.data.len().min(ctx.max_scan_bytes.min(DEFAULT_MAX_SCAN));
        let scan = &ctx.data[..scan_len];

        let mut entries: Vec<StringEntry> =
            extract_ascii(scan, ctx.min_string_len, ctx.max_strings, 0);
        let utf16 = extract_utf16le(scan, ctx.min_string_len, ctx.max_strings, 0);
        entries.extend(utf16);
        entries.sort_by(|left, right| {
            (left.offset, left.encoding.clone()).cmp(&(right.offset, right.encoding.clone()))
        });
        entries.truncate(ctx.max_strings);
        for entry in &mut entries {
            entry.section = section_for_offset(entry.offset, &artifact.sections);
        }

        let ascii_count = entries
            .iter()
            .filter(|entry| entry.encoding == "ascii")
            .count();
        let utf16_count = entries.len() - ascii_count;
        fragment.facts.insert("count".into(), json!(entries.len()));
        fragment
            .facts
            .insert("ascii_count".into(), json!(ascii_count));
        fragment
            .facts
            .insert("utf16le_count".into(), json!(utf16_count));
        fragment
            .facts
            .insert("scanned_bytes".into(), json!(scan_len));
        fragment
            .facts
            .insert("truncated".into(), json!(artifact.size as usize > scan_len));
        fragment
            .facts
            .insert("min_length".into(), json!(ctx.min_string_len));
        if (artifact.size as usize) > scan_len {
            fragment.warnings.push(format!(
                "strings: scanned only {scan_len} / {} bytes (max_scan_bytes); results are partial",
                artifact.size
            ));
        }
        fragment.strings = entries;
        fragment
    }
}
