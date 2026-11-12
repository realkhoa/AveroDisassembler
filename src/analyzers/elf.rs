//! ELF analyzer: sections + entropy, symbols/libraries, hardening flags.
//!
//! Uses goblin for parsing; findings are evidence-backed and explicitly confidence-scored.

use goblin::elf::program_header::{PF_W, PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_LOAD};
use goblin::elf::Elf;
use serde_json::json;

use crate::analyzers::{AnalysisContext, Analyzer, Fragment};
use crate::evidence::{loc, make_evidence};
use crate::findings::make_finding;
use crate::hashing::entropy_of;
use crate::ir::{Artifact, Export, Import, Kind, Section, Severity};

const EVIDENCE_ENGINE: &str = "avero.elf";

const SHT_NOBITS: u32 = 8;
const SHN_UNDEF: usize = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

fn machine_name(machine: u16) -> &'static str {
    match machine {
        3 => "x86",
        62 => "x86_64",
        40 => "arm",
        183 => "aarch64",
        8 => "mips",
        243 => "riscv",
        22 => "s390",
        21 => "ppc64",
        20 => "ppc",
        0 => "none",
        _ => "unknown",
    }
}

fn elf_type_name(elf_type: u16) -> &'static str {
    match elf_type {
        1 => "REL (relocatable)",
        2 => "EXEC (executable)",
        3 => "DYN (PIE/shared object)",
        4 => "CORE",
        _ => "other",
    }
}

fn section_bytes<'a>(data: &'a [u8], offset: u64, size: u64) -> &'a [u8] {
    let start = offset as usize;
    if start >= data.len() {
        return &[];
    }
    let end = start.saturating_add(size as usize).min(data.len());
    &data[start..end]
}

pub struct ElfAnalyzer;

impl Analyzer for ElfAnalyzer {
    fn id(&self) -> &'static str {
        "elf.structure"
    }

    fn accepts(&self, artifact: &Artifact) -> bool {
        artifact.has_kind(Kind::Elf)
    }

    fn priority(&self) -> i32 {
        10
    }

    fn run(&self, ctx: &AnalysisContext, _artifact: &Artifact) -> Fragment {
        let mut fragment = Fragment::default();
        let elf = match Elf::parse(ctx.data) {
            Ok(elf) => elf,
            Err(error) => {
                fragment
                    .unknowns
                    .push(format!("elf.structure: goblin parse failed: {error}"));
                fragment.facts.insert("parse_failed".into(), json!(true));
                return fragment;
            }
        };

        let data = ctx.data;
        let bits = if elf.is_64 { 64 } else { 32 };
        let endianness = if elf.little_endian { "little" } else { "big" };
        let machine = machine_name(elf.header.e_machine);
        let elf_type = elf.header.e_type;
        let entry = elf.entry;

        // ---- sections -----------------------------------------------------
        let mut section_evidence = Vec::new();
        for (index, header) in elf.section_headers.iter().enumerate() {
            if index == 0 {
                continue; // SHT_NULL
            }
            let name = elf
                .shdr_strtab
                .get_at(header.sh_name)
                .unwrap_or("")
                .to_string();
            let entropy = if header.sh_type == SHT_NOBITS {
                0.0
            } else {
                entropy_of(section_bytes(data, header.sh_offset, header.sh_size))
            };
            let mut flags = Vec::new();
            if header.sh_flags & 0x4 != 0 {
                flags.push("execute".to_string());
            }
            if header.sh_flags & 0x2 != 0 {
                flags.push("write".to_string());
            }
            if header.sh_flags & 0x1 != 0 {
                flags.push("alloc".to_string());
            }
            let evidence = make_evidence(
                EVIDENCE_ENGINE,
                env!("CARGO_PKG_VERSION"),
                "section",
                loc(vec![
                    ("name", json!(name)),
                    ("offset", json!(header.sh_offset)),
                    ("size", json!(header.sh_size)),
                ]),
                Some(format!("section {name}: entropy={entropy:.3}")),
                1.0,
                Vec::new(),
            );
            if entropy >= 7.2 && header.sh_size >= 1024 && header.sh_type != SHT_NOBITS {
                section_evidence.push(evidence.clone());
                fragment.findings.push(make_finding(
                    Severity::Medium,
                    "packing",
                    format!("ELF section `{name}` has high entropy ({entropy:.2})"),
                    "Entropy near 8 bits/byte is common in compressed/encrypted data or embedded payloads."
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
                    format!("ELF section `{name}` is both writable and executable"),
                    "Section has both write and execute permissions — usually self-modifying code/JIT or an unpacker.".to_string(),
                    &[&evidence],
                    0.7,
                    None,
                ));
            }
            fragment.sections.push(Section {
                name,
                va: header.sh_addr,
                vsize: header.sh_size,
                raw_offset: header.sh_offset,
                raw_size: header.sh_size,
                entropy,
                flags,
            });
        }

        // ---- hardening ----------------------------------------------------
        let mut nx = false;
        let mut exec_stack = false;
        let mut have_gnu_stack = false;
        let mut relro = false;
        let mut wx_load = false;
        for header in &elf.program_headers {
            match header.p_type {
                PT_GNU_STACK => {
                    have_gnu_stack = true;
                    if header.p_flags & PF_X as u32 != 0 {
                        exec_stack = true;
                    } else {
                        nx = true;
                    }
                }
                PT_GNU_RELRO => relro = true,
                PT_LOAD => {
                    let flags = header.p_flags;
                    if flags & PF_W as u32 != 0 && flags & PF_X as u32 != 0 {
                        wx_load = true;
                    }
                }
                _ => {}
            }
        }

        let mut symbol_count = 0usize;
        let mut canary = false;
        let mut fortify = 0usize;
        let mut exports: Vec<Export> = Vec::new();
        for symbol in elf.dynsyms.iter() {
            symbol_count += 1;
            let name = elf.dynstrtab.get_at(symbol.st_name).unwrap_or("");
            if name.contains("__stack_chk_fail") {
                canary = true;
            }
            if name.contains("_chk") {
                fortify += 1;
            }
            let bind = symbol.st_bind();
            if symbol.st_shndx != SHN_UNDEF && (bind == STB_GLOBAL || bind == STB_WEAK) {
                if !name.is_empty() && exports.len() < 200 {
                    exports.push(Export {
                        name: Some(name.to_string()),
                        ordinal: None,
                        rva: Some(symbol.st_value),
                        forwarder: None,
                    });
                }
            }
        }
        let symtab_symbols = elf.syms.iter().count();
        for symbol in elf.syms.iter() {
            let name = elf.strtab.get_at(symbol.st_name).unwrap_or("");
            if name.contains("__stack_chk_fail") {
                canary = true;
            }
            if name.contains("_chk") {
                fortify += 1;
            }
        }
        let stripped = symtab_symbols == 0;
        let static_linked = elf.interpreter.is_none() && elf.libraries.is_empty();

        for library in &elf.libraries {
            fragment.imports.push(Import {
                library: library.to_string(),
                name: None,
                ordinal: None,
                iat_rva: None,
            });
        }
        fragment.exports.extend(exports);

        let hardening_evidence = make_evidence(
            EVIDENCE_ENGINE,
            env!("CARGO_PKG_VERSION"),
            "metadata",
            loc(vec![
                ("pie", json!(elf_type == ET_DYN)),
                ("nx", json!(nx)),
                ("relro", json!(relro)),
                ("canary", json!(canary)),
            ]),
            Some(format!(
                "hardening: pie={} nx={} relro={} canary={}",
                elf_type == ET_DYN,
                nx,
                relro,
                canary
            )),
            1.0,
            Vec::new(),
        );

        if exec_stack {
            fragment.findings.push(make_finding(
                Severity::High,
                "hardening",
                "Executable stack (GNU_STACK has X permission)",
                "PT_GNU_STACK requests an executable stack — usually a build mistake or a shellcode loader."
                    .to_string(),
                &[&hardening_evidence],
                0.9,
                Some("Rebuild with `-z noexecstack`.".to_string()),
            ));
        } else if !have_gnu_stack {
            fragment.findings.push(make_finding(
                Severity::Low,
                "hardening",
                "No PT_GNU_STACK found (NX unknown)",
                "ELF does not declare GNU_STACK; NX may still be enabled but cannot be verified from the header.".to_string(),
                &[&hardening_evidence],
                0.5,
                None,
            ));
        }
        if elf_type == ET_EXEC {
            fragment.findings.push(make_finding(
                Severity::Low,
                "hardening",
                "Not a PIE (ET_EXEC)",
                "Binary is not a position-independent executable — ASLR applies with limitations."
                    .to_string(),
                &[&hardening_evidence],
                0.8,
                None,
            ));
        }
        if !relro {
            fragment.findings.push(make_finding(
                Severity::Low,
                "hardening",
                "No RELRO (PT_GNU_RELRO)",
                "RELRO is missing — the GOT can be overwritten if there is a memory corruption bug.".to_string(),
                &[&hardening_evidence],
                0.8,
                None,
            ));
        }
        if wx_load {
            fragment.findings.push(make_finding(
                Severity::High,
                "hardening",
                "PT_LOAD is both writable and executable (W+X segment)",
                "A loadable segment has write+execute permissions — unusual for an ordinary binary."
                    .to_string(),
                &[&hardening_evidence],
                0.8,
                None,
            ));
        }
        if static_linked {
            fragment.findings.push(make_finding(
                Severity::Info,
                "structure",
                if stripped {
                    "Static, stripped ELF"
                } else {
                    "Static ELF (no dynamic linking)"
                },
                "Static binary with no dynamic linker dependency — common in firmware/busybox/malware.".to_string(),
                &[&hardening_evidence],
                0.9,
                None,
            ));
        }
        for rpath in elf.rpaths.iter().chain(elf.runpaths.iter()) {
            let evidence = make_evidence(
                EVIDENCE_ENGINE,
                env!("CARGO_PKG_VERSION"),
                "metadata",
                loc(vec![("path", json!(rpath))]),
                Some(format!("RPATH/RUNPATH: {rpath}")),
                0.8,
                Vec::new(),
            );
            fragment.findings.push(make_finding(
                Severity::Low,
                "structure",
                format!("RPATH/RUNPATH: {rpath}"),
                "Dynamic library search path may be abused if it points to a writable directory."
                    .to_string(),
                &[&evidence],
                0.5,
                None,
            ));
            fragment.evidence.push(evidence);
        }
        if fragment
            .sections
            .iter()
            .any(|section| section.name.starts_with(".debug_"))
        {
            fragment.findings.push(make_finding(
                Severity::Info,
                "metadata",
                "Debug info present (.debug_* sections)",
                "Binary contains debug symbols — easier to read while reverse engineering."
                    .to_string(),
                &[&hardening_evidence],
                0.9,
                None,
            ));
        }

        // ---- facts / metadata --------------------------------------------
        fragment.facts.insert("bits".into(), json!(bits));
        fragment
            .facts
            .insert("endianness".into(), json!(endianness));
        fragment.facts.insert("machine".into(), json!(machine));
        fragment
            .facts
            .insert("elf_type".into(), json!(elf_type_name(elf_type)));
        fragment
            .facts
            .insert("entry".into(), json!(format!("0x{entry:x}")));
        fragment
            .facts
            .insert("section_count".into(), json!(fragment.sections.len()));
        fragment
            .facts
            .insert("symbol_count".into(), json!(symbol_count));
        fragment
            .facts
            .insert("symtab_symbol_count".into(), json!(symtab_symbols));
        fragment.facts.insert("stripped".into(), json!(stripped));
        fragment.facts.insert("static".into(), json!(static_linked));
        fragment
            .facts
            .insert("libraries".into(), json!(elf.libraries));
        fragment
            .facts
            .insert("interpreter".into(), json!(elf.interpreter.unwrap_or("")));
        fragment
            .facts
            .insert("soname".into(), json!(elf.soname.unwrap_or("")));
        fragment
            .facts
            .insert("pie".into(), json!(elf_type == ET_DYN));
        fragment.facts.insert("nx".into(), json!(nx));
        fragment.facts.insert("relro".into(), json!(relro));
        fragment.facts.insert("canary".into(), json!(canary));
        fragment
            .facts
            .insert("fortify_symbols".into(), json!(fortify));
        fragment
            .facts
            .insert("exports_count".into(), json!(fragment.exports.len()));

        fragment
            .metadata
            .insert("elf_machine".into(), json!(machine));
        fragment
            .metadata
            .insert("elf_type".into(), json!(elf_type_name(elf_type)));
        fragment.metadata.insert(
            "elf_interpreter".into(),
            json!(elf.interpreter.unwrap_or("")),
        );
        fragment
            .metadata
            .insert("elf_pie".into(), json!(elf_type == ET_DYN));
        fragment.metadata.insert("elf_nx".into(), json!(nx));
        fragment.metadata.insert("elf_relro".into(), json!(relro));
        fragment.metadata.insert("elf_canary".into(), json!(canary));
        fragment
            .metadata
            .insert("elf_stripped".into(), json!(stripped));

        let type_name = elf_type_name(elf_type);
        let header_evidence = make_evidence(
            EVIDENCE_ENGINE,
            env!("CARGO_PKG_VERSION"),
            "header",
            loc(vec![
                ("machine", json!(machine)),
                ("type", json!(type_name)),
            ]),
            Some(format!(
                "ELF {bits}-bit {endianness} {machine} {type_name}, entry=0x{entry:x}"
            )),
            1.0,
            Vec::new(),
        );
        fragment.evidence.push(header_evidence);
        fragment.evidence.push(hardening_evidence);
        fragment.evidence.extend(section_evidence);
        fragment
    }
}

/// Helper used by the probe/report layer when it needs a human ELF type label.
pub fn type_label(elf_type: u16) -> &'static str {
    elf_type_name(elf_type)
}
