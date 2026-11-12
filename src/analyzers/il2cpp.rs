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
        let mut parsed_summary: Option<(usize, usize)> = None;
        match crate::il2cpp::parse(ctx.data) {
            Ok(metadata) => {
                fragment
                    .facts
                    .insert("type_count".into(), json!(metadata.type_count));
                fragment
                    .facts
                    .insert("method_count".into(), json!(metadata.method_count));
                fragment
                    .facts
                    .insert("image_count".into(), json!(metadata.image_count));
                fragment.facts.insert(
                    "image_names".into(),
                    json!(metadata
                        .images
                        .iter()
                        .map(|image| image.name.clone())
                        .take(100)
                        .collect::<Vec<_>>()),
                );
                fragment.facts.insert(
                    "assembly_names".into(),
                    json!(metadata.assemblies.iter().take(100).collect::<Vec<_>>()),
                );
                fragment.facts.insert(
                    "types_sample".into(),
                    json!(metadata
                        .types_sample
                        .iter()
                        .take(200)
                        .map(|entry| if entry.namespace.is_empty() {
                            entry.name.clone()
                        } else {
                            format!("{}.{}", entry.namespace, entry.name)
                        })
                        .collect::<Vec<_>>()),
                );
                fragment.facts.insert(
                    "methods_sample".into(),
                    json!(metadata.methods_sample.iter().take(200).collect::<Vec<_>>()),
                );
                parsed_summary = Some((metadata.type_count, metadata.method_count));
            }
            Err(error) => {
                fragment
                    .unknowns
                    .push(format!("IL2CPP metadata parser: {error}"));
            }
        }
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
            match parsed_summary {
                Some((types, methods)) => format!(
                    "Unity IL2CPP metadata (version {version}, {types} types, {methods} methods)"
                ),
                None => format!("Unity IL2CPP metadata (version {version})"),
            },
            match parsed_summary {
                Some((types, methods)) => format!(
                    "Unity IL2CPP global-metadata.dat was parsed: {types} type definitions and {methods} method definitions are available in the report facts (types_sample/methods_sample). Method bodies are native and require the Cpp2IL sidecar for full IL recovery."
                ),
                None => "This is the global-metadata.dat of a Unity IL2CPP game. The version determines the header layout; dumping types/methods requires the matching parser or the Cpp2IL sidecar.".to_string(),
            },
            &[&evidence],
            0.9,
            None,
        ));
        if !supported {
            fragment.unknowns.push(format!(
                "IL2CPP metadata version {version} has not been verified — header layout may differ"
            ));
        }
        if parsed_summary.is_none() {
            fragment.unknowns.push(
                "IL2CPP type/method dump not available for this metadata file (see unknown above)"
                    .to_string(),
            );
        }
        fragment.evidence.push(evidence);
        fragment
    }
}
