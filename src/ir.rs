//! Unified intermediate representation (`avero.ir/v1`).
//!
//! Every analyzer returns data in these types; JSON/Markdown/HTML renderers and the CLI
//! consume the same structures. All maps are `BTreeMap` so serialization is deterministic.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const IR_VERSION: &str = "avero.ir/v1";
pub const REPORT_SCHEMA: &str = "avero.report/v1";
pub const TOOL_NAME: &str = "avero";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Artifact kinds. One file can have several (e.g. `Pe` + `DotNet`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Pe,
    Elf,
    MachO,
    DotNet,
    Apk,
    Dex,
    JavaClass,
    Zip,
    UnityIl2Cpp,
    UnityAssetBundle,
    GodotPck,
    UnrealPak,
    Firmware,
    Script,
    Wasm,
    PythonPyc,
    Unknown,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Pe => "pe",
            Kind::Elf => "elf",
            Kind::MachO => "macho",
            Kind::DotNet => "dotnet",
            Kind::Apk => "apk",
            Kind::Dex => "dex",
            Kind::JavaClass => "java_class",
            Kind::Zip => "zip",
            Kind::UnityIl2Cpp => "unity_il2cpp",
            Kind::UnityAssetBundle => "unity_asset_bundle",
            Kind::GodotPck => "godot_pck",
            Kind::UnrealPak => "unreal_pak",
            Kind::Firmware => "firmware",
            Kind::Script => "script",
            Kind::Wasm => "wasm",
            Kind::PythonPyc => "python_pyc",
            Kind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Higher is more severe; used for report ordering.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Producer {
    pub engine: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// A verifiable pointer to the bytes / metadata / engine output behind a claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub producer: Producer,
    pub kind: String,
    pub locator: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    pub confidence: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub va: u64,
    pub vsize: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub entropy: f64,
    #[serde(default)]
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub library: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat_rva: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rva: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    pub offset: u64,
    pub value: String,
    pub encoding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub detail: String,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    pub confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Artifact {
    pub ir_version: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub size: u64,
    pub kinds: Vec<Kind>,
    pub hashes: BTreeMap<String, String>,
    pub entropy: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endianness: Option<String>,
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
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub ir_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_id: String,
    pub tool: ToolInfo,
    pub generated_at: String,
    pub artifact: Artifact,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub facts: BTreeMap<String, Value>,
    #[serde(default)]
    pub coverage: BTreeMap<String, String>,
    #[serde(default)]
    pub unknowns: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl Report {
    pub fn new(artifact: Artifact) -> Self {
        Report {
            schema_id: REPORT_SCHEMA.to_string(),
            tool: ToolInfo {
                name: TOOL_NAME.to_string(),
                version: TOOL_VERSION.to_string(),
                ir_version: IR_VERSION.to_string(),
            },
            generated_at: crate::util::now_iso8601(),
            artifact,
            findings: Vec::new(),
            facts: BTreeMap::new(),
            coverage: BTreeMap::new(),
            unknowns: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

impl Artifact {
    pub fn has_kind(&self, kind: Kind) -> bool {
        self.kinds.contains(&kind)
    }

    pub fn kind_names(&self) -> String {
        self.kinds
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}
