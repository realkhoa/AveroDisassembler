//! Artifact probing: identify what a file *is* before analyzing it.
//!
//! The probe is dependency-light and defensive: it never executes the target and never
//! panics on malformed input. It is the single place that assigns [`Kind`] values.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::evidence::{loc, make_evidence};
use crate::hashing::digest;
use crate::ir::{Artifact, Evidence, Kind, IR_VERSION};
use crate::pehdr;
use crate::zipscan;

pub const PROBE_ENGINE: &str = "avero.probe";
pub const PROBE_VERSION: &str = env!("CARGO_PKG_VERSION");

const IL2CPP_METADATA_MAGIC: u32 = 0xFAB1_1BAF;

#[derive(Default)]
struct Detection {
    kinds: Vec<Kind>,
    architecture: Option<String>,
    bits: Option<u32>,
    endianness: Option<String>,
    metadata: BTreeMap<String, Value>,
    evidence: Vec<Evidence>,
}

impl Detection {
    fn add(&mut self, kind: Kind) {
        if !self.kinds.contains(&kind) {
            self.kinds.push(kind);
        }
    }

    fn evidence(
        &mut self,
        kind: &str,
        locator: BTreeMap<String, Value>,
        excerpt: String,
        confidence: f64,
    ) {
        self.evidence.push(make_evidence(
            PROBE_ENGINE,
            PROBE_VERSION,
            kind,
            locator,
            Some(excerpt),
            confidence,
            Vec::new(),
        ));
    }
}

fn u16_at(data: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(if little_endian {
        u16::from_le_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_be_bytes([bytes[0], bytes[1]])
    })
}

fn u32_at(data: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(if little_endian {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    })
}

fn u64_at(data: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(if little_endian {
        u64::from_le_bytes(bytes.try_into().ok()?)
    } else {
        u64::from_be_bytes(bytes.try_into().ok()?)
    })
}

// ------------------------------------------------------------------------------
// format detectors
// ------------------------------------------------------------------------------

fn detect_pe(data: &[u8], detection: &mut Detection) -> bool {
    let Some(info) = pehdr::parse(data) else {
        return false;
    };
    detection.add(Kind::Pe);
    let (arch, bits) = pehdr::machine_name(info.machine);
    detection.architecture = Some(if arch == "pe-machine" {
        format!("pe-machine-0x{:04x}", info.machine)
    } else {
        arch.to_string()
    });
    detection.bits = bits;
    detection.endianness = Some("little".to_string());

    let mut metadata = BTreeMap::new();
    metadata.insert("pe_header_offset".to_string(), json!(info.header_offset));
    metadata.insert(
        "pe_machine".to_string(),
        json!(format!("0x{:04x}", info.machine)),
    );
    metadata.insert("pe_sections".to_string(), json!(info.section_count));
    metadata.insert("pe_timestamp".to_string(), json!(info.timestamp));
    metadata.insert(
        "pe_optional_magic".to_string(),
        json!(format!("0x{:04x}", info.optional_magic)),
    );
    metadata.insert(
        "pe_characteristics".to_string(),
        json!(format!("0x{:04x}", info.characteristics)),
    );
    metadata.insert(
        "pe_is_dll".to_string(),
        json!((info.characteristics & 0x2000) != 0),
    );
    metadata.insert("pe_is_64bit".to_string(), json!(info.is_64));
    metadata.insert("pe_subsystem".to_string(), json!(info.subsystem));
    metadata.insert(
        "pe_entrypoint_rva".to_string(),
        json!(format!("0x{:x}", info.entry_rva)),
    );
    metadata.insert(
        "pe_image_base".to_string(),
        json!(format!("0x{:x}", info.image_base)),
    );
    metadata.insert(
        "pe_dll_characteristics".to_string(),
        json!(format!("0x{:04x}", info.dll_characteristics)),
    );
    metadata.insert(
        "pe_aslr".to_string(),
        json!((info.dll_characteristics & 0x0040) != 0),
    );
    metadata.insert(
        "pe_dep".to_string(),
        json!((info.dll_characteristics & 0x0100) != 0),
    );
    metadata.insert(
        "pe_cfg".to_string(),
        json!((info.dll_characteristics & 0x4000) != 0),
    );
    for (name, index) in [
        ("pe_export_dir_rva", 0usize),
        ("pe_import_dir_rva", 1),
        ("pe_resource_dir_rva", 2),
        ("pe_debug_dir_rva", 6),
    ] {
        if let Some((rva, _size)) = info.data_directory(index) {
            metadata.insert(name.to_string(), json!(rva));
        }
    }

    if let Some((cli_rva, cli_size)) = info.data_directory(14) {
        if cli_rva != 0 {
            detection.add(Kind::DotNet);
            metadata.insert("dotnet_cli_header_rva".to_string(), json!(cli_rva));
            metadata.insert("dotnet_cli_header_size".to_string(), json!(cli_size));
            let mut architecture = detection.architecture.clone();
            let mut bits = detection.bits;
            if let Some(offset) = info.rva_to_offset(cli_rva) {
                if let Some(flags) = u32_at(data, offset + 16, true) {
                    metadata.insert(
                        "dotnet_cor_flags".to_string(),
                        json!(format!("0x{flags:04x}")),
                    );
                    metadata.insert("dotnet_il_only".to_string(), json!((flags & 0x1) != 0));
                    if !info.is_64 && (flags & 0x1) != 0 {
                        if (flags & 0x2) != 0 || (flags & 0x20000) != 0 {
                            architecture = Some("x86".to_string());
                            bits = Some(32);
                        } else {
                            architecture = Some("anycpu".to_string());
                            bits = None;
                        }
                    }
                }
            }
            detection.architecture = architecture;
            detection.bits = bits;
        }
    }
    detection.metadata.extend(metadata);

    detection.evidence(
        "header",
        loc(vec![
            ("e_lfanew", json!(info.header_offset)),
            ("machine", json!(format!("0x{:04x}", info.machine))),
        ]),
        format!(
            "PE header at 0x{:x}, machine 0x{:04x}, {} sections",
            info.header_offset, info.machine, info.section_count
        ),
        1.0,
    );
    true
}

const ELF_MACHINES: &[(u16, &str, Option<u32>)] = &[
    (3, "x86", Some(32)),
    (62, "x86_64", Some(64)),
    (40, "arm", Some(32)),
    (183, "aarch64", Some(64)),
    (8, "mips", Some(32)),
    (243, "riscv", None),
    (22, "s390", None),
    (21, "ppc64", Some(64)),
    (20, "ppc", Some(32)),
];

fn detect_elf(data: &[u8], detection: &mut Detection) -> bool {
    if data.len() < 52 || &data[..4] != b"\x7fELF" {
        return false;
    }
    detection.add(Kind::Elf);
    let class = data[4];
    let data_encoding = data[5];
    let little_endian = data_encoding == 1;
    let bits = if class == 2 { Some(64) } else { Some(32) };
    let e_type = u16_at(data, 16, little_endian).unwrap_or(0);
    let e_machine = u16_at(data, 18, little_endian).unwrap_or(0);
    let (arch, _) = ELF_MACHINES
        .iter()
        .find(|(machine, _, _)| *machine == e_machine)
        .map(|(_, name, bits)| (*name, *bits))
        .unwrap_or(("elf-machine", None));
    detection.architecture = Some(if arch == "elf-machine" {
        format!("elf-machine-{e_machine}")
    } else {
        arch.to_string()
    });
    detection.bits = bits;
    detection.endianness = Some(if little_endian { "little" } else { "big" }.to_string());
    let entry = if bits == Some(64) {
        u64_at(data, 24, little_endian).unwrap_or(0)
    } else {
        u32_at(data, 24, little_endian).unwrap_or(0) as u64
    };
    let metadata = &mut detection.metadata;
    metadata.insert("elf_class".to_string(), json!(bits));
    metadata.insert(
        "elf_endianness".to_string(),
        json!(if little_endian { "little" } else { "big" }),
    );
    metadata.insert("elf_type".to_string(), json!(e_type));
    metadata.insert("elf_machine".to_string(), json!(e_machine));
    metadata.insert("elf_entry".to_string(), json!(format!("0x{entry:x}")));
    detection.evidence(
        "header",
        loc(vec![("offset", json!(0)), ("magic", json!("7f454c46"))]),
        format!(
            "ELF {}-bit {} e_type={} e_machine={}",
            bits.unwrap_or(0),
            detection.architecture.clone().unwrap_or_default(),
            e_type,
            e_machine
        ),
        1.0,
    );
    true
}

const MACHO_CPUS: &[(u32, &str, Option<u32>)] = &[
    (7, "x86", Some(32)),
    (0x0100_0007, "x86_64", Some(64)),
    (12, "arm", Some(32)),
    (0x0100_000C, "aarch64", Some(64)),
    (18, "ppc", Some(32)),
    (0x0100_0012, "ppc64", Some(64)),
];

fn detect_macho(data: &[u8], detection: &mut Detection) -> bool {
    if data.len() < 28 {
        return false;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let is_thin = matches!(magic, 0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE);
    let is_fat = matches!(magic, 0xCAFE_BABE | 0xBEBA_FECA);
    if !is_thin && !is_fat {
        return false;
    }
    detection.add(Kind::MachO);
    if is_fat {
        let nfat = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if !(1..32).contains(&nfat) {
            // 0xCAFEBABE with an implausible arch count is a Java class file, not Mach-O.
            detection.kinds.retain(|kind| *kind != Kind::MachO);
            return false;
        }
        detection.endianness = Some("big".to_string());
        detection
            .metadata
            .insert("macho_fat".to_string(), json!(true));
        detection
            .metadata
            .insert("macho_arch_count".to_string(), json!(nfat));
        detection.evidence(
            "header",
            loc(vec![("offset", json!(0))]),
            format!("Mach-O universal binary with {nfat} architectures"),
            1.0,
        );
        return true;
    }
    let little_endian = matches!(magic, 0xCEFA_EDFE | 0xCFFA_EDFE);
    let is_64 = matches!(magic, 0xFEED_FACF | 0xCFFA_EDFE);
    let cputype = u32_at(data, 4, little_endian).unwrap_or(0);
    let filetype = u32_at(data, 12, little_endian).unwrap_or(0);
    let (arch, bits) = MACHO_CPUS
        .iter()
        .find(|(cpu, _, _)| *cpu == cputype)
        .map(|(_, name, bits)| (*name, *bits))
        .unwrap_or(("macho-cpu", None));
    detection.architecture = Some(if arch == "macho-cpu" {
        format!("macho-cpu-0x{cputype:x}")
    } else {
        arch.to_string()
    });
    detection.bits = bits.or(if is_64 { Some(64) } else { Some(32) });
    detection.endianness = Some(if little_endian { "little" } else { "big" }.to_string());
    detection
        .metadata
        .insert("macho_cputype".to_string(), json!(format!("0x{cputype:x}")));
    detection
        .metadata
        .insert("macho_filetype".to_string(), json!(filetype));
    detection.evidence(
        "header",
        loc(vec![("offset", json!(0))]),
        format!(
            "Mach-O {}-bit {} filetype={}",
            detection.bits.unwrap_or(0),
            detection.architecture.clone().unwrap_or_default(),
            filetype
        ),
        1.0,
    );
    true
}

fn detect_il2cpp(data: &[u8], detection: &mut Detection) -> bool {
    if data.len() < 8 {
        return false;
    }
    let magic = u32_at(data, 0, true).unwrap_or(0);
    if magic != IL2CPP_METADATA_MAGIC {
        return false;
    }
    let version = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    detection.add(Kind::UnityIl2Cpp);
    detection
        .metadata
        .insert("il2cpp_metadata_version".to_string(), json!(version));
    detection
        .metadata
        .insert("il2cpp_magic".to_string(), json!(format!("0x{magic:08x}")));
    detection.evidence(
        "header",
        loc(vec![
            ("offset", json!(0)),
            ("magic", json!(format!("0x{magic:08x}"))),
        ]),
        format!("Unity IL2CPP global-metadata.dat, version {version}"),
        1.0,
    );
    true
}

fn detect_game_container(data: &[u8], detection: &mut Detection) -> bool {
    if data.starts_with(b"GDPC") {
        detection.add(Kind::GodotPck);
        let version = u32_at(data, 4, true).unwrap_or(0);
        detection
            .metadata
            .insert("godot_pck_version".to_string(), json!(version));
        detection.evidence(
            "header",
            loc(vec![("offset", json!(0))]),
            format!("Godot PCK archive, format version {version}"),
            1.0,
        );
        return true;
    }
    if data.starts_with(b"UnityFS") {
        detection.add(Kind::UnityAssetBundle);
        detection
            .metadata
            .insert("unity_bundle".to_string(), json!(true));
        detection.evidence(
            "header",
            loc(vec![("offset", json!(0))]),
            "UnityFS asset bundle header".to_string(),
            1.0,
        );
        return true;
    }
    false
}

fn detect_java_class(data: &[u8], detection: &mut Detection) -> bool {
    if data.len() < 10 || &data[..4] != b"\xca\xfe\xba\xbe" {
        return false;
    }
    let major = u16_at(data, 6, false).unwrap_or(0);
    if !(45..=80).contains(&major) {
        return false;
    }
    let minor = u16_at(data, 4, false).unwrap_or(0);
    detection.add(Kind::JavaClass);
    detection
        .metadata
        .insert("java_class_major".to_string(), json!(major));
    detection
        .metadata
        .insert("java_class_minor".to_string(), json!(minor));
    detection.evidence(
        "header",
        loc(vec![("offset", json!(0))]),
        format!("Java class file, major version {major}"),
        1.0,
    );
    true
}

fn detect_zip(data: &[u8], detection: &mut Detection) -> bool {
    let Some(info) = zipscan::scan(data) else {
        return false;
    };
    if info.entries.is_empty() && !data.starts_with(b"PK\x03\x04") {
        return false;
    }
    let names: Vec<String> = info
        .entries
        .iter()
        .map(|entry| entry.name.clone())
        .collect();
    let lower: Vec<String> = names.iter().map(|name| name.to_ascii_lowercase()).collect();
    let has_manifest = lower.iter().any(|name| name == "androidmanifest.xml");
    let dex_files: Vec<&String> = names
        .iter()
        .filter(|name| name.to_ascii_lowercase().ends_with(".dex"))
        .collect();
    let is_apk = has_manifest || !dex_files.is_empty();
    if is_apk {
        detection.add(Kind::Apk);
        if !dex_files.is_empty() {
            detection.add(Kind::Dex);
        }
    } else {
        detection.add(Kind::Zip);
    }

    let mut abis: Vec<String> = names
        .iter()
        .filter_map(|name| {
            let parts: Vec<&str> = name.split('/').collect();
            if parts.len() >= 3 && parts[0].eq_ignore_ascii_case("lib") {
                Some(parts[1].to_string())
            } else {
                None
            }
        })
        .collect();
    abis.sort();
    abis.dedup();
    let signed_v1 = names.iter().any(|name| {
        let upper = name.to_ascii_uppercase();
        upper.starts_with("META-INF/")
            && (upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC"))
    });
    let compressed: u64 = info.entries.iter().map(|entry| entry.compressed_size).sum();
    let uncompressed: u64 = info
        .entries
        .iter()
        .map(|entry| entry.uncompressed_size)
        .sum();
    let ratio = if compressed > 0 {
        (uncompressed as f64 / compressed as f64 * 1000.0).round() / 1000.0
    } else {
        0.0
    };
    let metadata = &mut detection.metadata;
    metadata.insert("zip_entries".to_string(), json!(names.len()));
    metadata.insert("zip_has_android_manifest".to_string(), json!(has_manifest));
    metadata.insert("zip_dex_count".to_string(), json!(dex_files.len()));
    metadata.insert("zip_native_abis".to_string(), json!(abis));
    metadata.insert(
        "zip_has_resources_arsc".to_string(),
        json!(names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("resources.arsc"))),
    );
    metadata.insert("zip_signed_v1".to_string(), json!(signed_v1));
    metadata.insert("zip_apk_sig_block".to_string(), json!(info.apk_sig_block));
    metadata.insert("zip_compression_ratio".to_string(), json!(ratio));
    detection.evidence(
        "metadata",
        loc(vec![("zip_entries", json!(names.len()))]),
        format!(
            "ZIP container with {} entries (manifest={has_manifest}, dex={})",
            names.len(),
            dex_files.len()
        ),
        1.0,
    );
    true
}

const FIRMWARE_MAGICS: &[(&[u8], &str)] = &[
    (b"hsqs", "squashfs-le"),
    (b"sqsh", "squashfs-be"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"\x27\x05\x19\x56", "uimage"),
    (b"ANDROID!", "android-boot"),
    (b"UBI#", "ubi"),
    (b"CrAU", "chromeos-update"),
];

fn detect_firmware(data: &[u8], detection: &mut Detection) -> bool {
    for (magic, label) in FIRMWARE_MAGICS {
        if data.starts_with(magic) {
            detection.add(Kind::Firmware);
            detection
                .metadata
                .insert("firmware_container".to_string(), json!(label));
            detection.evidence(
                "header",
                loc(vec![("offset", json!(0))]),
                format!("Container magic {label} at offset 0x0"),
                1.0,
            );
            return true;
        }
    }
    if data.len() > 0x48 && data[0x40..0x44] == *b"_FVH" {
        detection.add(Kind::Firmware);
        detection
            .metadata
            .insert("firmware_container".to_string(), json!("uefi-fv"));
        detection.evidence(
            "header",
            loc(vec![("offset", json!(0x40))]),
            "UEFI firmware volume signature (_FVH)".to_string(),
            0.9,
        );
        return true;
    }
    false
}

fn detect_misc(data: &[u8], detection: &mut Detection) -> bool {
    if data.starts_with(b"\x00asm") {
        detection.add(Kind::Wasm);
        return true;
    }
    if data.len() >= 4 && data[1..4] == [0x0d, 0x0d, 0x0a] {
        detection.add(Kind::PythonPyc);
        detection.metadata.insert(
            "python_pyc_magic".to_string(),
            json!(hex::encode(&data[..4])),
        );
        return true;
    }
    false
}

fn detect_script(data: &[u8], detection: &mut Detection) -> bool {
    let sample = &data[..data.len().min(4096)];
    if sample.is_empty() || sample.contains(&0) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(sample) else {
        return false;
    };
    let printable = text
        .chars()
        .filter(|ch| ch.is_ascii_graphic() || matches!(ch, ' ' | '\r' | '\n' | '\t'))
        .count();
    let total_chars = text.chars().count();
    if total_chars == 0 || (printable as f64) / (total_chars as f64) < 0.9 {
        return false;
    }
    detection.add(Kind::Script);
    if let Some(first_line) = text.lines().next() {
        if first_line.starts_with("#!") {
            detection
                .metadata
                .insert("script_shebang".to_string(), json!(first_line));
        }
    }
    true
}

// ------------------------------------------------------------------------------
// public API
// ------------------------------------------------------------------------------

fn detect(data: &[u8], detection: &mut Detection) -> bool {
    if detect_pe(data, detection) {
        return true;
    }
    if detect_elf(data, detection) {
        return true;
    }
    if detect_macho(data, detection) {
        return true;
    }
    if detect_il2cpp(data, detection) {
        return true;
    }
    if detect_game_container(data, detection) {
        return true;
    }
    if detect_java_class(data, detection) {
        return true;
    }
    if detect_zip(data, detection) {
        return true;
    }
    if detect_firmware(data, detection) {
        return true;
    }
    if detect_misc(data, detection) {
        return true;
    }
    if detect_script(data, detection) {
        return true;
    }
    false
}

/// Probe a file on disk.
pub fn probe(path: &Path) -> Result<Artifact> {
    let data =
        std::fs::read(path).with_context(|| format!("cannot read artifact: {}", path.display()))?;
    Ok(probe_bytes(&data, Some(path)))
}

/// Probe an in-memory artifact (used by tests and by callers that already mapped the file).
pub fn probe_bytes(data: &[u8], path: Option<&Path>) -> Artifact {
    let digest = digest(data);
    let mut detection = Detection::default();
    if !detect(data, &mut detection) {
        detection.add(Kind::Unknown);
    }

    let mut hashes = BTreeMap::new();
    hashes.insert("md5".to_string(), digest.md5.clone());
    hashes.insert("sha1".to_string(), digest.sha1.clone());
    hashes.insert("sha256".to_string(), digest.sha256.clone());

    let mut evidence = detection.evidence;
    evidence.push(make_evidence(
        PROBE_ENGINE,
        PROBE_VERSION,
        "heuristic",
        loc(vec![
            ("size", json!(digest.size)),
            ("entropy", json!(digest.entropy)),
        ]),
        Some(format!(
            "size={} entropy={:.4} kinds={}",
            digest.size,
            digest.entropy,
            detection
                .kinds
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>()
                .join(",")
        )),
        1.0,
        Vec::new(),
    ));

    Artifact {
        ir_version: IR_VERSION.to_string(),
        id: digest.sha256.clone(),
        path: path.map(|value| value.to_string_lossy().to_string()),
        size: digest.size,
        kinds: detection.kinds,
        hashes,
        entropy: digest.entropy,
        architecture: detection.architecture,
        bits: detection.bits,
        endianness: detection.endianness,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        metadata: detection.metadata,
        evidence,
    }
}

pub fn human_kinds(artifact: &Artifact) -> String {
    if artifact.kinds.is_empty() {
        return "unknown".to_string();
    }
    artifact
        .kinds
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_elf_header() {
        let mut data = vec![0u8; 128];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        data[16..18].copy_from_slice(&2u16.to_le_bytes());
        data[18..20].copy_from_slice(&62u16.to_le_bytes());
        let artifact = probe_bytes(&data, None);
        assert!(artifact.has_kind(Kind::Elf));
        assert_eq!(artifact.architecture.as_deref(), Some("x86_64"));
    }

    #[test]
    fn probes_il2cpp_metadata() {
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(&IL2CPP_METADATA_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&29i32.to_le_bytes());
        let artifact = probe_bytes(&data, None);
        assert!(artifact.has_kind(Kind::UnityIl2Cpp));
        assert_eq!(
            artifact.metadata.get("il2cpp_metadata_version"),
            Some(&json!(29))
        );
    }

    #[test]
    fn probes_script() {
        let artifact = probe_bytes(b"#!/usr/bin/env python3\nprint('hi')\n", None);
        assert!(artifact.has_kind(Kind::Script));
    }

    #[test]
    fn probes_unknown() {
        let artifact = probe_bytes(&[0u8, 1, 2, 3, 4, 5, 6, 7], None);
        assert!(artifact.has_kind(Kind::Unknown));
    }
}
