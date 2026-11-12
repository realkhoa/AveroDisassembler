//! Format matrix + determinism tests for the pure-Rust core.

use avero::ir::Kind;
use avero::pipeline::{analyze, ScanOptions};
use avero::probe::probe_bytes;

fn minimal_elf() -> Vec<u8> {
    let mut data = vec![0u8; 128];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2; // 64-bit
    data[5] = 1; // little endian
    data[16..18].copy_from_slice(&2u16.to_le_bytes());
    data[18..20].copy_from_slice(&62u16.to_le_bytes());
    data
}

fn minimal_macho() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(&0xCFFA_EDFEu32.to_be_bytes());
    data[4..8].copy_from_slice(&0x0100_000Cu32.to_le_bytes());
    data[12..16].copy_from_slice(&2u32.to_le_bytes());
    data
}

fn minimal_pe() -> Vec<u8> {
    let mut data = vec![0u8; 0x400];
    data[..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    data[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());
    let optional = coff + 20;
    data[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
    data[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    data[optional + 24..optional + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
    data
}

fn minimal_il2cpp() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(&0xFAB1_1BAFu32.to_le_bytes());
    data[4..8].copy_from_slice(&29i32.to_le_bytes());
    data
}

fn minimal_godot_pck() -> Vec<u8> {
    let mut data = b"GDPC".to_vec();
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 128]);
    data
}

fn push_u16(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(target: &mut Vec<u8>, value: u32) {
    target.extend_from_slice(&value.to_le_bytes());
}

/// Build a small STORED zip; only what Avero's central-directory reader needs.
fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut local = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let offset = local.len() as u32;
        local.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut local, 20);
        push_u16(&mut local, 0);
        push_u16(&mut local, 0); // stored
        push_u16(&mut local, 0);
        push_u16(&mut local, 0);
        push_u32(&mut local, 0); // crc (ignored by Avero)
        push_u32(&mut local, data.len() as u32);
        push_u32(&mut local, data.len() as u32);
        push_u16(&mut local, name.len() as u16);
        push_u16(&mut local, 0);
        local.extend_from_slice(name.as_bytes());
        local.extend_from_slice(data);

        central.extend_from_slice(b"PK\x01\x02");
        push_u16(&mut central, 20);
        push_u16(&mut central, 20);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, data.len() as u32);
        push_u32(&mut central, data.len() as u32);
        push_u16(&mut central, name.len() as u16);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, offset);
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = local.len() as u32;
    let cd_size = central.len() as u32;
    local.extend_from_slice(&central);
    local.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut local, 0);
    push_u16(&mut local, 0);
    push_u16(&mut local, entries.len() as u16);
    push_u16(&mut local, entries.len() as u16);
    push_u32(&mut local, cd_size);
    push_u32(&mut local, cd_offset);
    push_u16(&mut local, 0);
    local
}

fn apk_bytes() -> Vec<u8> {
    make_zip(&[
        ("AndroidManifest.xml", b"\x03\x00\x08\x00dummy-manifest"),
        ("classes.dex", b"dex\n035\x00dummy"),
        ("resources.arsc", b"\x02\x00\x0c\x00dummy"),
        ("lib/arm64-v8a/libtarget.so", b"\x7fELF\x02\x01\x01\x00"),
    ])
}

#[test]
fn probes_supported_formats() {
    let cases: Vec<(&str, Vec<u8>, Kind)> = vec![
        ("elf", minimal_elf(), Kind::Elf),
        ("macho", minimal_macho(), Kind::MachO),
        ("pe", minimal_pe(), Kind::Pe),
        ("il2cpp", minimal_il2cpp(), Kind::UnityIl2Cpp),
        ("godot", minimal_godot_pck(), Kind::GodotPck),
        ("apk", apk_bytes(), Kind::Apk),
        ("wasm", b"\x00asm\x01\x00\x00\x00".to_vec(), Kind::Wasm),
        (
            "script",
            b"#!/usr/bin/env python3\nprint(1)\n".to_vec(),
            Kind::Script,
        ),
        ("pyc", b"B\r\r\n\x00\x00\x00\x00".to_vec(), Kind::PythonPyc),
    ];
    for (name, data, expected) in cases {
        let artifact = probe_bytes(&data, None);
        assert!(
            artifact.has_kind(expected),
            "{name}: expected {expected:?}, got {:?}",
            artifact.kinds
        );
    }
}

#[test]
fn scan_apk_runs_analyzer_and_is_deterministic() {
    let data = apk_bytes();
    let options = ScanOptions {
        use_cache: false,
        ..ScanOptions::default()
    };
    let report_one = {
        let mut artifact = probe_bytes(&data, None);
        analyze(&mut artifact, &data, &options)
    };
    let report_two = {
        let mut artifact = probe_bytes(&data, None);
        analyze(&mut artifact, &data, &options)
    };
    assert_eq!(
        report_one.coverage.get("apk.structure").map(String::as_str),
        Some("ok")
    );
    assert_eq!(
        report_one.facts["apk.structure"]["dex_count"],
        serde_json::json!(1)
    );
    assert_eq!(
        avero::report::to_deterministic_json(&report_one),
        avero::report::to_deterministic_json(&report_two)
    );
}

#[test]
fn scan_pe_detects_sections_and_imports_only_when_present() {
    let data = minimal_pe();
    let mut artifact = probe_bytes(&data, None);
    let options = ScanOptions {
        use_cache: false,
        ..ScanOptions::default()
    };
    let report = analyze(&mut artifact, &data, &options);
    assert_eq!(
        report.coverage.get("pe.structure").map(String::as_str),
        Some("ok")
    );
    // minimal PE has one section header that is all zeroes / out of bounds; must not panic
    assert!(report.artifact.sections.len() <= 1);
}

#[test]
fn unknown_artifacts_still_report() {
    let data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let mut artifact = probe_bytes(&data, None);
    assert!(artifact.has_kind(Kind::Unknown));
    let options = ScanOptions {
        use_cache: false,
        ..ScanOptions::default()
    };
    let report = analyze(&mut artifact, &data, &options);
    assert!(report.coverage.contains_key("strings.generic"));
    assert!(!report.unknowns.is_empty());
}
