//! Mach-O analyzer: segments/sections, dylibs, code-signature and encryption state.

use goblin::mach::load_command::CommandVariant;
use goblin::mach::{Mach, MachO};
use serde_json::json;

use crate::analyzers::{AnalysisContext, Analyzer, Fragment};
use crate::evidence::{loc, make_evidence};
use crate::findings::make_finding;
use crate::hashing::entropy_of;
use crate::ir::{Artifact, Import, Kind, Section, Severity};

const EVIDENCE_ENGINE: &str = "avero.macho";

const MH_PIE: u32 = 0x0020_0000;
const MH_EXECUTE: u32 = 2;
const MH_DYLIB: u32 = 6;
const MH_BUNDLE: u32 = 8;

fn cpu_name(cputype: u32) -> &'static str {
    match cputype {
        7 => "x86",
        0x0100_0007 => "x86_64",
        12 => "arm",
        0x0100_000C => "aarch64",
        18 => "ppc",
        0x0100_0012 => "ppc64",
        _ => "unknown",
    }
}

fn filetype_name(filetype: u32) -> &'static str {
    match filetype {
        1 => "MH_OBJECT",
        2 => "MH_EXECUTE",
        6 => "MH_DYLIB",
        8 => "MH_BUNDLE",
        9 => "MH_DYLINKER",
        11 => "MH_KEXT_BUNDLE",
        _ => "MH_OTHER",
    }
}

fn segment_permissions(initprot: u32) -> Vec<String> {
    let mut output = Vec::new();
    if initprot & 0x1 != 0 {
        output.push("read".to_string());
    }
    if initprot & 0x2 != 0 {
        output.push("write".to_string());
    }
    if initprot & 0x4 != 0 {
        output.push("execute".to_string());
    }
    output
}

pub struct MachOAnalyzer;

impl Analyzer for MachOAnalyzer {
    fn id(&self) -> &'static str {
        "macho.structure"
    }

    fn accepts(&self, artifact: &Artifact) -> bool {
        artifact.has_kind(Kind::MachO)
    }

    fn priority(&self) -> i32 {
        10
    }

    fn run(&self, ctx: &AnalysisContext, _artifact: &Artifact) -> Fragment {
        let mut fragment = Fragment::default();
        let parsed = match Mach::parse(ctx.data) {
            Ok(mach) => mach,
            Err(error) => {
                fragment
                    .unknowns
                    .push(format!("macho.structure: goblin parse failed: {error}"));
                return fragment;
            }
        };
        match parsed {
            Mach::Binary(macho) => analyze_binary(&mut fragment, ctx.data, &macho, "binary"),
            Mach::Fat(fat) => {
                let count = fat.narches;
                let arches = fat.arches().unwrap_or_default();
                let arch_names: Vec<String> = arches
                    .iter()
                    .map(|arch| format!("{} ({})", cpu_name(arch.cputype), arch.cpusubtype))
                    .collect();
                fragment.facts.insert("fat".into(), json!(true));
                fragment.facts.insert("arch_count".into(), json!(count));
                fragment
                    .facts
                    .insert("architectures".into(), json!(arch_names));
                let evidence = make_evidence(
                    EVIDENCE_ENGINE,
                    env!("CARGO_PKG_VERSION"),
                    "header",
                    loc(vec![("arch_count", json!(count))]),
                    Some(format!(
                        "Mach-O universal binary with {count} architectures: {}",
                        arch_names.join(", ")
                    )),
                    1.0,
                    Vec::new(),
                );
                fragment.findings.push(make_finding(
                    Severity::Info,
                    "structure",
                    format!("Universal (fat) Mach-O: {count} architectures"),
                    "Binary contains multiple architectures (common in iOS/macOS apps shipped for multiple platforms).".to_string(),
                    &[&evidence],
                    0.9,
                    None,
                ));
                fragment.evidence.push(evidence);
                // Analyze the first architecture slice for sections/hardening facts.
                if let Some(arch) = arches.first() {
                    let slice = arch.slice(ctx.data);
                    if let Ok(Mach::Binary(macho)) = Mach::parse(slice) {
                        analyze_binary(&mut fragment, ctx.data, &macho, "fat-slice-0");
                    }
                }
            }
        }
        fragment
    }
}

fn analyze_binary(fragment: &mut Fragment, data: &[u8], macho: &MachO, scope: &str) {
    let bits = if macho.is_64 { 64 } else { 32 };
    let cputype = macho.header.cputype;
    let filetype = macho.header.filetype;
    let flags = macho.header.flags;
    let cpu = cpu_name(cputype);
    let pie = flags & MH_PIE != 0;

    let mut signed = false;
    let mut encrypted = false;
    for load in &macho.load_commands {
        match &load.command {
            CommandVariant::CodeSignature(_) => signed = true,
            CommandVariant::EncryptionInfo32(info) if info.cryptid != 0 => encrypted = true,
            CommandVariant::EncryptionInfo64(info) if info.cryptid != 0 => encrypted = true,
            _ => {}
        }
    }

    // ---- segments / sections -------------------------------------------
    let mut section_evidence = Vec::new();
    let mut wx_segment: Option<String> = None;
    for segment in &macho.segments {
        let segname = segment.name().unwrap_or("").to_string();
        let permissions = segment_permissions(segment.initprot);
        let writable = permissions.iter().any(|value| value == "write");
        let executable = permissions.iter().any(|value| value == "execute");
        if writable && executable && wx_segment.is_none() {
            wx_segment = Some(segname.clone());
        }
        if let Ok(sections) = segment.sections() {
            for (section, _section_data) in sections {
                let name = section.name().unwrap_or("").to_string();
                let offset = section.offset as u64;
                let size = section.size;
                let start = offset as usize;
                let entropy = if start < data.len() {
                    let end = start.saturating_add(size as usize).min(data.len());
                    entropy_of(&data[start..end])
                } else {
                    0.0
                };
                let mut section_flags = permissions.clone();
                if !segname.is_empty() {
                    section_flags.push(format!("seg:{segname}"));
                }
                let evidence = make_evidence(
                    EVIDENCE_ENGINE,
                    env!("CARGO_PKG_VERSION"),
                    "section",
                    loc(vec![
                        ("name", json!(name)),
                        ("offset", json!(offset)),
                        ("size", json!(size)),
                    ]),
                    Some(format!("section {segname},{name}: entropy={entropy:.3}")),
                    1.0,
                    Vec::new(),
                );
                if entropy >= 7.2 && size >= 1024 {
                    section_evidence.push(evidence.clone());
                    fragment.findings.push(make_finding(
                        Severity::Medium,
                        "packing",
                        format!("Mach-O section `{segname},{name}` has high entropy ({entropy:.2})"),
                        "Entropy near 8 bits/byte usually indicates compressed/encrypted data or an embedded payload."
                            .to_string(),
                        &[&evidence],
                        0.6,
                        None,
                    ));
                }
                fragment.sections.push(Section {
                    name: format!("{segname},{name}"),
                    va: section.addr,
                    vsize: size,
                    raw_offset: offset,
                    raw_size: size,
                    entropy,
                    flags: section_flags,
                });
            }
        }
    }

    for library in &macho.libs {
        fragment.imports.push(Import {
            library: library.to_string(),
            name: None,
            ordinal: None,
            iat_rva: None,
        });
    }

    let symbol_count = macho.symbols().count();
    let hardening_evidence = make_evidence(
        EVIDENCE_ENGINE,
        env!("CARGO_PKG_VERSION"),
        "metadata",
        loc(vec![
            ("pie", json!(pie)),
            ("signed", json!(signed)),
            ("encrypted", json!(encrypted)),
        ]),
        Some(format!(
            "hardening: pie={pie} signed={signed} encrypted={encrypted}"
        )),
        1.0,
        Vec::new(),
    );

    if encrypted {
        fragment.findings.push(make_finding(
            Severity::High,
            "encryption",
            "Encrypted Mach-O (FairPlay/App Store)",
            "LC_ENCRYPTION_INFO has cryptid != 0 — the binary is encrypted; dump it from memory to analyze.".to_string(),
            &[&hardening_evidence],
            0.9,
            None,
        ));
    }
    let is_executable = matches!(filetype, MH_EXECUTE | MH_DYLIB | MH_BUNDLE);
    if is_executable && !signed {
        fragment.findings.push(make_finding(
            Severity::Medium,
            "signature",
            "Mach-O has no code signature",
            "No LC_CODE_SIGNATURE found — the binary may have been modified/patched or built unsigned."
                .to_string(),
            &[&hardening_evidence],
            0.8,
            None,
        ));
    }
    if filetype == MH_EXECUTE && !pie {
        fragment.findings.push(make_finding(
            Severity::Low,
            "hardening",
            "PIE not enabled (MH_PIE)",
            "Executable has no MH_PIE — ASLR applies with limitations.".to_string(),
            &[&hardening_evidence],
            0.8,
            None,
        ));
    }
    if let Some(segment) = &wx_segment {
        fragment.findings.push(make_finding(
            Severity::High,
            "hardening",
            format!("Segment `{segment}` is both writable and executable"),
            "Segment has write+execute permissions — unusual for an ordinary binary (JIT/unpacker)."
                .to_string(),
            &[&hardening_evidence],
            0.8,
            None,
        ));
    }
    for rpath in &macho.rpaths {
        let evidence = make_evidence(
            EVIDENCE_ENGINE,
            env!("CARGO_PKG_VERSION"),
            "metadata",
            loc(vec![("rpath", json!(rpath))]),
            Some(format!("LC_RPATH: {rpath}")),
            0.7,
            Vec::new(),
        );
        fragment.findings.push(make_finding(
            Severity::Low,
            "structure",
            format!("RPATH: {rpath}"),
            "Dynamic dylib search path — check whether it points to a writable directory."
                .to_string(),
            &[&evidence],
            0.5,
            None,
        ));
        fragment.evidence.push(evidence);
    }

    fragment.facts.insert("bits".into(), json!(bits));
    fragment.facts.insert("cpu".into(), json!(cpu));
    fragment
        .facts
        .insert("filetype".into(), json!(filetype_name(filetype)));
    fragment.facts.insert("pie".into(), json!(pie));
    fragment.facts.insert("signed".into(), json!(signed));
    fragment.facts.insert("encrypted".into(), json!(encrypted));
    fragment.facts.insert("libs".into(), json!(macho.libs));
    fragment.facts.insert("rpaths".into(), json!(macho.rpaths));
    fragment
        .facts
        .insert("section_count".into(), json!(fragment.sections.len()));
    fragment
        .facts
        .insert("symbol_count".into(), json!(symbol_count));
    fragment
        .facts
        .insert("entry".into(), json!(format!("0x{:x}", macho.entry)));
    fragment.metadata.insert("macho_cpu".into(), json!(cpu));
    fragment
        .metadata
        .insert("macho_filetype".into(), json!(filetype_name(filetype)));
    fragment.metadata.insert("macho_pie".into(), json!(pie));
    fragment
        .metadata
        .insert("macho_signed".into(), json!(signed));
    fragment
        .metadata
        .insert("macho_encrypted".into(), json!(encrypted));
    fragment.metadata.insert("macho_scope".into(), json!(scope));

    let header_evidence = make_evidence(
        EVIDENCE_ENGINE,
        env!("CARGO_PKG_VERSION"),
        "header",
        loc(vec![
            ("cpu", json!(cpu)),
            ("filetype", json!(filetype_name(filetype))),
        ]),
        Some(format!(
            "Mach-O {bits}-bit {cpu} {}, entry=0x{:x}",
            filetype_name(filetype),
            macho.entry
        )),
        1.0,
        Vec::new(),
    );
    fragment.evidence.push(header_evidence);
    fragment.evidence.push(hardening_evidence);
    fragment.evidence.extend(section_evidence);
}
