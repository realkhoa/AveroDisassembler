//! Analyzer tests added in v0.3: ELF, Mach-O and the native signature engine.

use avero::pipeline::{analyze, ScanOptions};
use avero::probe::probe_bytes;

fn put_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Minimal but valid ELF64 with .text + .shstrtab and PT_LOAD + PT_GNU_STACK.
fn elf_with_sections() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2; // 64-bit
    data[5] = 1; // little endian
    data[6] = 1; // ELF version
    put_u16(&mut data, 16, 2); // ET_EXEC
    put_u16(&mut data, 18, 62); // x86-64
    put_u32(&mut data, 20, 1);
    put_u64(&mut data, 24, 0x401000); // entry
    put_u64(&mut data, 32, 64); // phoff
    put_u64(&mut data, 40, 176); // shoff
    put_u16(&mut data, 52, 64); // ehsize
    put_u16(&mut data, 54, 56); // phentsize
    put_u16(&mut data, 56, 2); // phnum
    put_u16(&mut data, 58, 64); // shentsize
    put_u16(&mut data, 60, 3); // shnum
    put_u16(&mut data, 62, 2); // shstrndx

    // PT_LOAD (read+execute)
    let ph1 = 64;
    put_u32(&mut data, ph1, 1);
    put_u32(&mut data, ph1 + 4, 5);
    put_u64(&mut data, ph1 + 8, 368);
    put_u64(&mut data, ph1 + 16, 0x401000);
    put_u64(&mut data, ph1 + 24, 0x401000);
    put_u64(&mut data, ph1 + 32, 16);
    put_u64(&mut data, ph1 + 40, 16);
    put_u64(&mut data, ph1 + 48, 0x1000);
    // PT_GNU_STACK (read+write, non-exec -> NX)
    let ph2 = 64 + 56;
    put_u32(&mut data, ph2, 0x6474_e551);
    put_u32(&mut data, ph2 + 4, 6);

    // .text at 368
    data[368..384].copy_from_slice(&[0x90u8; 16]);
    // .shstrtab at 384: "\0.text\0.shstrtab\0"
    let names = b"\0.text\0.shstrtab\0";
    data[384..384 + names.len()].copy_from_slice(names);

    // section headers at 176
    let sh_text = 176 + 64;
    put_u32(&mut data, sh_text, 1);
    put_u32(&mut data, sh_text + 4, 1);
    put_u64(&mut data, sh_text + 8, 0x6);
    put_u64(&mut data, sh_text + 16, 0x401000);
    put_u64(&mut data, sh_text + 24, 368);
    put_u64(&mut data, sh_text + 32, 16);
    put_u64(&mut data, sh_text + 48, 16);
    let sh_names = 176 + 128;
    put_u32(&mut data, sh_names, 7);
    put_u32(&mut data, sh_names + 4, 3);
    put_u64(&mut data, sh_names + 24, 384);
    put_u64(&mut data, sh_names + 32, names.len() as u64);
    put_u64(&mut data, sh_names + 48, 1);
    data
}

fn minimal_macho() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(&0xCFFA_EDFEu32.to_be_bytes());
    data[4..8].copy_from_slice(&0x0100_000Cu32.to_le_bytes());
    data[12..16].copy_from_slice(&2u32.to_le_bytes());
    data
}

fn scan_report(data: &[u8]) -> avero::ir::Report {
    let mut artifact = probe_bytes(data, None);
    let options = ScanOptions {
        use_cache: false,
        ..ScanOptions::default()
    };
    analyze(&mut artifact, data, &options)
}

#[test]
fn elf_analyzer_reports_sections_and_hardening() {
    let data = elf_with_sections();
    let report = scan_report(&data);
    assert_eq!(
        report.coverage.get("elf.structure").map(String::as_str),
        Some("ok")
    );
    assert!(
        report
            .artifact
            .sections
            .iter()
            .any(|section| section.name == ".text"),
        "sections: {:?}",
        report.artifact.sections
    );
    let facts = &report.facts["elf.structure"];
    assert_eq!(facts["bits"], 64);
    assert_eq!(facts["machine"], "x86_64");
    assert_eq!(facts["nx"], true);
    assert_eq!(facts["pie"], false);
}

#[test]
fn macho_analyzer_reports_minimal_binary() {
    let data = minimal_macho();
    let report = scan_report(&data);
    assert_eq!(
        report.coverage.get("macho.structure").map(String::as_str),
        Some("ok")
    );
    let facts = &report.facts["macho.structure"];
    assert_eq!(facts["bits"], 64);
    assert_eq!(facts["cpu"], "aarch64");
    assert_eq!(facts["filetype"], "MH_EXECUTE");
    assert_eq!(facts["pie"], false);
    assert!(
        report.findings.iter().any(
            |finding| finding.title.contains("code signature") || finding.title.contains("PIE")
        ),
        "findings: {:?}",
        report.findings
    );
}

#[test]
fn signature_rules_match_upx_markers() {
    let data = b"MZ....UPX0....UPX1....UPX!....".to_vec();
    let report = scan_report(&data);
    assert_eq!(
        report.coverage.get("signatures.rules").map(String::as_str),
        Some("ok")
    );
    let facts = &report.facts["signatures.rules"];
    let matched = facts["matched_rules"].as_array().expect("array");
    assert!(
        matched.iter().any(|value| value == "upx_packer"),
        "matched rules: {matched:?}"
    );
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.title.contains("upx_packer")));
}

#[test]
fn signature_rules_do_not_match_clean_binary() {
    let data = minimal_macho();
    let report = scan_report(&data);
    let matched = report.facts["signatures.rules"]["matched_rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(matched.is_empty(), "unexpected matches: {matched:?}");
}
