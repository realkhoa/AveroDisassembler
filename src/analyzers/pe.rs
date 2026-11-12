//! PE structure analyzer: sections + entropy, imports/exports, security flags and
//! evidence-backed heuristics.
//!
//! Header parsing is manual (`pehdr`) so a malformed PE still yields triage; goblin is
//! used only for the import/export tables.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use goblin::pe::PE;
use regex::Regex;
use serde_json::json;

use crate::analyzers::{AnalysisContext, Analyzer, Fragment};
use crate::evidence::{loc, make_evidence};
use crate::findings::make_finding;
use crate::hashing::entropy_of;
use crate::ir::{Artifact, Export, Import, Kind, Section, Severity};
use crate::pehdr;

const EVIDENCE_ENGINE: &str = "pehdr+goblin";

const SECTION_EXECUTE: u32 = 0x2000_0000;
const SECTION_READ: u32 = 0x4000_0000;
const SECTION_WRITE: u32 = 0x8000_0000;
const SECTION_CODE: u32 = 0x0000_0020;
const SECTION_INITIALIZED_DATA: u32 = 0x0000_0040;
const SECTION_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const SECTION_DISCARDABLE: u32 = 0x0200_0000;

const ANTI_DEBUG_IMPORTS: &[&str] = &[
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "DebugActiveProcess",
    "NtSetInformationThread",
    "SetUnhandledExceptionFilter",
];

const INJECTION_IMPORTS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "SetThreadContext",
    "QueueUserAPC",
    "NtUnmapViewOfSection",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
];

const NETWORK_IMPORTS: &[&str] = &[
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "WinHttpOpen",
    "WSAStartup",
    "connect",
    "send",
    "recv",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
];

const CRYPTO_IMPORTS: &[&str] = &[
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptAcquireContextA",
    "BCryptEncrypt",
    "BCryptDecrypt",
];

fn packer_section_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?i)(upx|aspack|mpress|themida|vmp|enigma|petite|nsp|pec|packed|\.pack|\.ccg|\.boom|\.obf)",
        )
        .expect("valid packer regex")
    })
}

fn section_flags(characteristics: u32) -> Vec<String> {
    let mut flags = Vec::new();
    for (mask, name) in [
        (SECTION_CODE, "code"),
        (SECTION_INITIALIZED_DATA, "initialized-data"),
        (SECTION_UNINITIALIZED_DATA, "uninitialized-data"),
        (SECTION_DISCARDABLE, "discardable"),
        (SECTION_EXECUTE, "execute"),
        (SECTION_READ, "read"),
        (SECTION_WRITE, "write"),
    ] {
        if characteristics & mask != 0 {
            flags.push(name.to_string());
        }
    }
    flags
}

fn section_data<'a>(data: &'a [u8], raw_offset: u32, raw_size: u32) -> &'a [u8] {
    let start = raw_offset as usize;
    if start >= data.len() {
        return &[];
    }
    let end = start.saturating_add(raw_size as usize).min(data.len());
    &data[start..end]
}

pub struct PeAnalyzer;

impl Analyzer for PeAnalyzer {
    fn id(&self) -> &'static str {
        "pe.structure"
    }

    fn accepts(&self, artifact: &Artifact) -> bool {
        artifact.has_kind(Kind::Pe)
    }

    fn priority(&self) -> i32 {
        10
    }

    fn run(&self, ctx: &AnalysisContext, artifact: &Artifact) -> Fragment {
        let mut fragment = Fragment::default();
        let Some(info) = pehdr::parse(ctx.data) else {
            fragment
                .unknowns
                .push("pe.structure: pehdr could not parse the PE header".to_string());
            return fragment;
        };

        let data = ctx.data;
        let mut section_evidence = Vec::new();
        for raw in &info.sections {
            let bytes = section_data(data, raw.raw_offset, raw.raw_size);
            let entropy = if raw.raw_size > 0 {
                entropy_of(bytes)
            } else {
                0.0
            };
            let flags = section_flags(raw.characteristics);
            let evidence = make_evidence(
                EVIDENCE_ENGINE,
                env!("CARGO_PKG_VERSION"),
                "section",
                loc(vec![
                    ("name", json!(raw.name)),
                    ("raw_offset", json!(raw.raw_offset)),
                    ("raw_size", json!(raw.raw_size)),
                ]),
                Some(format!(
                    "section {}: entropy={:.3} flags={}",
                    raw.name,
                    entropy,
                    flags.join(",")
                )),
                1.0,
                Vec::new(),
            );

            if entropy >= 7.2 && raw.raw_size >= 1024 {
                section_evidence.push(evidence.clone());
                fragment.findings.push(make_finding(
                    Severity::Medium,
                    "packing",
                    format!("Section `{}` has high entropy ({:.2})", raw.name, entropy),
                    "Entropy near 8 bits/byte is common in compressed/encrypted data (packer, protector, embedded resource). \
                     Not enough to conclude packing — also check section permissions, the import table and runtime behavior."
                        .to_string(),
                    &[&evidence],
                    0.6,
                    None,
                ));
            }
            if flags.iter().any(|flag| flag == "execute")
                && flags.iter().any(|flag| flag == "write")
            {
                section_evidence.push(evidence.clone());
                fragment.findings.push(make_finding(
                    Severity::High,
                    "hardening",
                    format!("Section `{}` is both writable and executable (W+X)", raw.name),
                    "Section has both write and execute permissions. This is a common sign of an unpacker/shellcode \
                     or self-modifying code; it can also be legitimate JIT."
                        .to_string(),
                    &[&evidence],
                    0.7,
                    None,
                ));
            }
            if packer_section_pattern().is_match(&raw.name) {
                section_evidence.push(evidence.clone());
                fragment.findings.push(make_finding(
                    Severity::High,
                    "packing",
                    format!("Section name looks like a packer: `{}`", raw.name),
                    "Section name matches common packer/protector patterns (UPX, ASPack, Themida, VMProtect, ...)."
                        .to_string(),
                    &[&evidence],
                    0.75,
                    None,
                ));
            }

            fragment.sections.push(Section {
                name: raw.name.clone(),
                va: raw.va as u64,
                vsize: raw.vsize as u64,
                raw_offset: raw.raw_offset as u64,
                raw_size: raw.raw_size as u64,
                entropy,
                flags,
            });
        }

        let section_table_evidence = make_evidence(
            EVIDENCE_ENGINE,
            env!("CARGO_PKG_VERSION"),
            "section",
            loc(vec![("count", json!(info.sections.len()))]),
            Some(
                info.sections
                    .iter()
                    .take(16)
                    .map(|section| format!("{}@0x{:x}", section.name, section.va))
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
            1.0,
            Vec::new(),
        );

        // ---- metadata -----------------------------------------------------
        let timestamp = info.timestamp;
        let timestamp_iso = crate::util::iso8601_from_unix(timestamp as i64);
        let is_dll = (info.characteristics & 0x2000) != 0;
        fragment.metadata.insert(
            "pe_machine".into(),
            json!(format!("0x{:04x}", info.machine)),
        );
        fragment
            .metadata
            .insert("pe_timestamp".into(), json!(timestamp));
        fragment
            .metadata
            .insert("pe_timestamp_utc".into(), json!(timestamp_iso));
        fragment
            .metadata
            .insert("pe_subsystem".into(), json!(info.subsystem));
        fragment.metadata.insert("pe_is_dll".into(), json!(is_dll));
        fragment
            .metadata
            .insert("pe_is_64bit".into(), json!(info.is_64));
        fragment.metadata.insert(
            "pe_entrypoint_rva".into(),
            json!(format!("0x{:x}", info.entry_rva)),
        );
        fragment.metadata.insert(
            "pe_image_base".into(),
            json!(format!("0x{:x}", info.image_base)),
        );
        fragment.metadata.insert(
            "pe_dll_characteristics".into(),
            json!(format!("0x{:04x}", info.dll_characteristics)),
        );
        fragment.metadata.insert(
            "pe_aslr".into(),
            json!((info.dll_characteristics & 0x0040) != 0),
        );
        fragment.metadata.insert(
            "pe_dep".into(),
            json!((info.dll_characteristics & 0x0100) != 0),
        );
        fragment.metadata.insert(
            "pe_cfg".into(),
            json!((info.dll_characteristics & 0x4000) != 0),
        );
        fragment.metadata.insert(
            "pe_overlay_offset".into(),
            json!(overlay_offset(&info).unwrap_or(0)),
        );

        // ---- imports / exports (goblin) -----------------------------------
        let mut import_evidence = None;
        let mut imported_names: BTreeSet<String> = BTreeSet::new();
        let mut rich_header = None;
        match PE::parse(data) {
            Ok(pe) => {
                for import in &pe.imports {
                    let name = if import.name.is_empty() {
                        None
                    } else {
                        Some(import.name.to_string())
                    };
                    if let Some(ref value) = name {
                        imported_names.insert(value.clone());
                    }
                    fragment.imports.push(Import {
                        library: import.dll.to_string(),
                        name,
                        ordinal: if import.ordinal > 0 {
                            Some(import.ordinal as u32)
                        } else {
                            None
                        },
                        iat_rva: Some(import.rva as u64),
                    });
                }
                for export in &pe.exports {
                    fragment.exports.push(Export {
                        name: export.name.map(|value| value.to_string()),
                        ordinal: None,
                        rva: Some(export.rva as u64),
                        forwarder: None,
                    });
                }
                rich_header = Some(pe.header.rich_header.is_some());
                if let Some(header) = &pe.header.rich_header {
                    let metadatas: Vec<String> = header
                        .metadatas()
                        .filter_map(|metadata| metadata.ok())
                        .take(20)
                        .map(|metadata| {
                            format!(
                                "product=0x{:04x} build={} count={}",
                                metadata.product, metadata.build, metadata.use_count
                            )
                        })
                        .collect();
                    fragment
                        .metadata
                        .insert("pe_rich_header_entries".into(), json!(metadatas.len()));
                }
                if !fragment.imports.is_empty() {
                    import_evidence = Some(make_evidence(
                        EVIDENCE_ENGINE,
                        env!("CARGO_PKG_VERSION"),
                        "metadata",
                        loc(vec![
                            (
                                "libraries",
                                json!(fragment
                                    .imports
                                    .iter()
                                    .map(|i| i.library.clone())
                                    .collect::<BTreeSet<_>>()
                                    .len()),
                            ),
                            ("imports", json!(fragment.imports.len())),
                        ]),
                        Some(
                            fragment
                                .imports
                                .iter()
                                .take(20)
                                .map(|i| i.library.clone())
                                .collect::<BTreeSet<_>>()
                                .into_iter()
                                .collect::<Vec<_>>()
                                .join(", "),
                        ),
                        1.0,
                        Vec::new(),
                    ));
                }
            }
            Err(error) => {
                fragment.warnings.push(format!(
                    "pe.structure: goblin could not parse import/export table: {error}"
                ));
            }
        }
        let rich_header_present = rich_header.unwrap_or_else(|| {
            data.get(..1024)
                .map(|head| zipscan_find(head, b"Rich"))
                .unwrap_or(false)
        });
        fragment
            .metadata
            .insert("pe_rich_header".into(), json!(rich_header_present));
        fragment
            .metadata
            .insert("pe_import_count".into(), json!(fragment.imports.len()));
        fragment
            .metadata
            .insert("pe_export_count".into(), json!(fragment.exports.len()));

        let has_tls = info
            .data_directory(9)
            .map(|(rva, _)| rva != 0)
            .unwrap_or(false);
        let has_signature = info
            .data_directory(4)
            .map(|(rva, _)| rva != 0)
            .unwrap_or(false);
        fragment
            .metadata
            .insert("pe_has_tls".into(), json!(has_tls));
        fragment
            .metadata
            .insert("pe_authenticode".into(), json!(has_signature));

        fragment
            .facts
            .insert("machine".into(), json!(format!("0x{:04x}", info.machine)));
        fragment
            .facts
            .insert("section_count".into(), json!(fragment.sections.len()));
        fragment
            .facts
            .insert("import_count".into(), json!(fragment.imports.len()));
        fragment
            .facts
            .insert("export_count".into(), json!(fragment.exports.len()));
        fragment
            .facts
            .insert("timestamp_utc".into(), json!(timestamp_iso));
        fragment.facts.insert(
            "aslr".into(),
            json!((info.dll_characteristics & 0x0040) != 0),
        );
        fragment.facts.insert(
            "dep".into(),
            json!((info.dll_characteristics & 0x0100) != 0),
        );
        fragment.facts.insert(
            "cfg".into(),
            json!((info.dll_characteristics & 0x4000) != 0),
        );
        fragment
            .facts
            .insert("rich_header".into(), json!(rich_header_present));

        // ---- findings ------------------------------------------------------
        if let Some(evidence) = &import_evidence {
            let anti_debug: Vec<&str> = ANTI_DEBUG_IMPORTS
                .iter()
                .copied()
                .filter(|name| imported_names.contains(*name))
                .collect();
            if !anti_debug.is_empty() {
                fragment.findings.push(make_finding(
                    Severity::Medium,
                    "anti-analysis",
                    "Import API anti-debugging",
                    format!(
                        "Binary imports APIs commonly used to detect debuggers: {}. This may be legitimate protection (DRM/anti-cheat) or malware.",
                        anti_debug.join(", ")
                    ),
                    &[evidence],
                    0.55,
                    Some("Inspect call sites before concluding; debug in an isolated environment.".to_string()),
                ));
            }
            let injection: Vec<&str> = INJECTION_IMPORTS
                .iter()
                .copied()
                .filter(|name| imported_names.contains(*name))
                .collect();
            if injection.len() >= 2 {
                fragment.findings.push(make_finding(
                    Severity::High,
                    "suspicious-api",
                    "Process injection API cluster",
                    format!(
                        "Combination of APIs commonly used to inject/execute code into another process: {}",
                        injection.join(", ")
                    ),
                    &[evidence],
                    0.6,
                    None,
                ));
            }
            let network: Vec<&str> = NETWORK_IMPORTS
                .iter()
                .copied()
                .filter(|name| imported_names.contains(*name))
                .collect();
            if !network.is_empty() {
                fragment.findings.push(make_finding(
                    Severity::Low,
                    "network",
                    "Network API imports",
                    format!(
                        "Binary imports network APIs: {}",
                        network
                            .iter()
                            .take(12)
                            .copied()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    &[evidence],
                    0.5,
                    None,
                ));
            }
            let crypto: Vec<&str> = CRYPTO_IMPORTS
                .iter()
                .copied()
                .filter(|name| imported_names.contains(*name))
                .collect();
            if !crypto.is_empty() {
                fragment.findings.push(make_finding(
                    Severity::Info,
                    "crypto",
                    "Import API crypto",
                    format!(
                        "Binary imports crypto APIs: {}",
                        crypto
                            .iter()
                            .take(12)
                            .copied()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    &[evidence],
                    0.5,
                    None,
                ));
            }
        }

        if (info.dll_characteristics & 0x0040) == 0 {
            fragment.findings.push(make_finding(
                Severity::Low,
                "hardening",
                "ASLR not enabled (DYNAMICBASE)",
                "PE does not enable DYNAMICBASE — the binary will load at a fixed address."
                    .to_string(),
                &[],
                0.9,
                None,
            ));
        }
        if (info.dll_characteristics & 0x0100) == 0 {
            fragment.findings.push(make_finding(
                Severity::Low,
                "hardening",
                "DEP not enabled (NXCOMPAT)",
                "PE does not enable NXCOMPAT — stack/heap may be executable.".to_string(),
                &[],
                0.9,
                None,
            ));
        }

        let suspicious_timestamp = timestamp == 0 || timestamp as i64 > now_unix() as i64;
        if suspicious_timestamp {
            if artifact.has_kind(Kind::DotNet) {
                fragment.findings.push(make_finding(
                    Severity::Info,
                    "metadata",
                    "PE timestamp is not real time (deterministic .NET build)",
                    format!(
                        "PE timestamp = {timestamp} ({timestamp_iso}). Roslyn uses a hash-derived timestamp for deterministic builds, so this value is often in the future — not an anomaly."
                    ),
                    &[],
                    0.8,
                    None,
                ));
            } else {
                fragment.findings.push(make_finding(
                    Severity::Low,
                    "metadata",
                    "Unusual compile timestamp",
                    format!("PE timestamp = {timestamp} ({timestamp_iso}) — may have been modified or produced by a synthetic build."),
                    &[],
                    0.5,
                    None,
                ));
            }
        }

        if let Some(end) = overlay_offset(&info) {
            let overlay_size = artifact.size.saturating_sub(end);
            if overlay_size > 4096 && overlay_size * 10 > artifact.size {
                let evidence = make_evidence(
                    EVIDENCE_ENGINE,
                    env!("CARGO_PKG_VERSION"),
                    "section",
                    loc(vec![
                        ("overlay_offset", json!(end)),
                        ("overlay_size", json!(overlay_size)),
                    ]),
                    Some(format!(
                        "overlay: {overlay_size} bytes at file offset 0x{end:x}"
                    )),
                    1.0,
                    Vec::new(),
                );
                fragment
                    .metadata
                    .insert("pe_overlay_size".into(), json!(overlay_size));
                fragment.findings.push(make_finding(
                    Severity::Info,
                    "structure",
                    "Large data overlay present",
                    format!(
                        "{overlay_size} bytes of data after the last section (overlay) — usually an installer/self-extracting archive or embedded payload."
                    ),
                    &[&evidence],
                    0.6,
                    None,
                ));
            }
        }
        if has_tls {
            fragment.findings.push(make_finding(
                Severity::Info,
                "structure",
                "TLS callback directory present",
                "TLS callbacks run before the entry point — a common technique to run code early/anti-debug.".to_string(),
                &[],
                0.6,
                None,
            ));
        }
        if has_signature {
            fragment.findings.push(make_finding(
                Severity::Info,
                "signature",
                "Authenticode signature present",
                "PE has a security directory (Authenticode signature). Verify the certificate's validity, not just its presence.".to_string(),
                &[],
                0.7,
                None,
            ));
        }

        fragment.evidence.push(section_table_evidence);
        if let Some(evidence) = import_evidence {
            fragment.evidence.push(evidence);
        }
        fragment.evidence.extend(section_evidence);
        fragment.facts.insert(
            "import_libraries".into(),
            json!(fragment
                .imports
                .iter()
                .map(|import| import.library.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()),
        );
        fragment.facts.insert(
            "section_entropy".into(),
            json!(fragment
                .sections
                .iter()
                .map(|section| (
                    section.name.clone(),
                    json!((section.entropy * 1000.0).round() / 1000.0)
                ))
                .collect::<std::collections::BTreeMap<_, _>>()),
        );
        fragment
    }
}

fn overlay_offset(info: &pehdr::PeInfo) -> Option<u64> {
    info.sections
        .iter()
        .map(|section| section.raw_offset as u64 + section.raw_size as u64)
        .max()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn zipscan_find(haystack: &[u8], needle: &[u8]) -> bool {
    crate::zipscan::find_subslice(haystack, needle).is_some()
}
