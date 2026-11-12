//! Unity IL2CPP metadata analyzer (header-level triage).

use serde_json::json;

use crate::analyzers::{AnalysisContext, Analyzer, Fragment};
use crate::evidence::{loc, make_evidence};
use crate::findings::make_finding;
use crate::ir::{Artifact, Kind, Severity};

const ENGINE: &str = "avero.il2cpp";
const MAGIC: u32 = 0xFAB1_1BAF;

pub struct Il2CppAnalyzer;

impl Analyzer for Il2CppAnalyzer {
    fn id(&self) -> &'static str {
        "unity.il2cpp"
    }

    fn accepts(&self, artifact: &Artifact) -> bool {
        artifact.has_kind(Kind::UnityIl2Cpp)
    }

    fn priority(&self) -> i32 {
        12
    }

    fn run(&self, ctx: &AnalysisContext, artifact: &Artifact) -> Fragment {
        let mut fragment = Fragment::default();
        if ctx.data.len() < 8 {
            fragment
                .unknowns
                .push("unity.il2cpp: file too small to contain a metadata header".to_string());
            return fragment;
        }
        let version = artifact
            .metadata
            .get("il2cpp_metadata_version")
            .and_then(|value| value.as_i64())
            .unwrap_or_else(|| {
                i32::from_le_bytes([ctx.data[4], ctx.data[5], ctx.data[6], ctx.data[7]]) as i64
            });
        let supported = matches!(
            version,
            19 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 31
        );
        fragment
            .facts
            .insert("metadata_version".into(), json!(version));
        fragment
            .facts
            .insert("version_supported".into(), json!(supported));
        fragment
            .facts
            .insert("file_size".into(), json!(ctx.data.len()));
        fragment
            .metadata
            .insert("il2cpp_metadata_version".into(), json!(version));
        let evidence = make_evidence(
            ENGINE,
            env!("CARGO_PKG_VERSION"),
            "header",
            loc(vec![
                ("magic", json!(format!("0x{MAGIC:08x}"))),
                ("version", json!(version)),
            ]),
            Some(format!(
                "IL2CPP global-metadata.dat, sanity=0x{MAGIC:08x}, version={version}"
            )),
            1.0,
            Vec::new(),
        );
        fragment.findings.push(make_finding(
            Severity::Info,
            "unity",
            format!("Unity IL2CPP metadata (version {version})"),
            "This is the global-metadata.dat of a Unity IL2CPP game. The version determines the header layout; \
             dumping types/methods requires the matching parser (phase P3). The Cpp2IL sidecar can be used to extract types/methods."
                .to_string(),
            &[&evidence],
            0.9,
            None,
        ));
        if !supported {
            fragment.unknowns.push(format!(
                "IL2CPP metadata version {version} has not been verified — header layout may differ"
            ));
        }
        fragment
            .unknowns
            .push("IL2CPP type/method dump not run yet (phase P3)".to_string());
        fragment.evidence.push(evidence);
        fragment
    }
}
