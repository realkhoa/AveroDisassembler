//! APK manifest integration test: real APK generated with aapt2 from our own manifest.

use avero::axml;
use avero::pipeline::{analyze, ScanOptions};
use avero::probe::probe_bytes;

const APK: &[u8] = include_bytes!("fixtures/sample.apk");
const MANIFEST: &[u8] = include_bytes!("fixtures/AndroidManifest.bin");
const SIGNED_APK: &[u8] = include_bytes!("fixtures/sample-signed.apk");
const RES_APK: &[u8] = include_bytes!("fixtures/sample-res.apk");

fn scan_apk() -> avero::ir::Report {
    let mut artifact = probe_bytes(APK, None);
    let options = ScanOptions {
        use_cache: false,
        ..ScanOptions::default()
    };
    analyze(&mut artifact, APK, &options)
}

#[test]
fn apk_probe_detects_apk() {
    let artifact = probe_bytes(APK, None);
    assert!(artifact.has_kind(avero::ir::Kind::Apk));
}

#[test]
fn apk_analyzer_parses_binary_manifest() {
    let report = scan_apk();
    assert_eq!(
        report.coverage.get("apk.structure").map(String::as_str),
        Some("ok")
    );
    let facts = &report.facts["apk.structure"];
    assert_eq!(facts["apk_package"], "com.avero.testsample");
    assert_eq!(facts["apk_version_code"], 7);
    assert_eq!(facts["apk_version_name"], "1.2.3");
    assert_eq!(facts["apk_min_sdk"], 24);
    assert_eq!(facts["apk_target_sdk"], 34);
    assert_eq!(facts["apk_debuggable"], true);
    assert_eq!(facts["apk_allow_backup"], false);
    let permissions = facts["apk_permissions"].as_array().expect("permissions");
    assert!(permissions
        .iter()
        .any(|value| value == "android.permission.INTERNET"));
    let dangerous = facts["apk_dangerous_permissions"]
        .as_array()
        .expect("dangerous");
    assert!(dangerous
        .iter()
        .any(|value| value == "android.permission.READ_SMS"));
    assert!(facts["apk_component_count"].as_u64().unwrap_or(0) >= 4);
    let exported = facts["apk_exported_components"]
        .as_array()
        .expect("exported");
    assert!(exported
        .iter()
        .any(|value| value.as_str().unwrap_or("").contains("MainActivity")));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.title.contains("debuggable")));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.title.contains("exported component")));
}

#[test]
fn apk_signature_and_resources_are_parsed() {
    let mut artifact = probe_bytes(SIGNED_APK, None);
    let report = analyze(
        &mut artifact,
        SIGNED_APK,
        &ScanOptions {
            use_cache: false,
            ..ScanOptions::default()
        },
    );
    let facts = &report.facts["apk.structure"];
    let schemes = facts["apk_signature_schemes"]
        .as_array()
        .expect("signature schemes");
    assert!(schemes.iter().any(|value| value == "v2"));
    assert!(schemes.iter().any(|value| value == "v3"));
    let signers = facts["apk_signers"].as_array().expect("signers");
    assert_eq!(signers.len(), 1, "certificates are deduplicated");
    assert!(signers[0]["subject"]
        .as_str()
        .unwrap_or("")
        .contains("Avero Test Cert"));
    let resources = &facts["apk_resources"];
    assert_eq!(resources["package"], "com.avero.signed");
    assert!(resources["strings"]
        .as_array()
        .expect("resource strings")
        .iter()
        .any(|entry| entry["value"] == "Avero Signed Sample"));

    // Unsigned fixture with resources: resources parse, no signatures.
    let mut artifact = probe_bytes(RES_APK, None);
    let report = analyze(
        &mut artifact,
        RES_APK,
        &ScanOptions {
            use_cache: false,
            ..ScanOptions::default()
        },
    );
    let facts = &report.facts["apk.structure"];
    assert!(facts["apk_signature_schemes"]
        .as_array()
        .map(|schemes| schemes.is_empty())
        .unwrap_or(true));
    assert_eq!(facts["apk_resources"]["package"], "com.avero.signed");
}

#[test]
fn manifest_parses_standalone() {
    let manifest = axml::parse_manifest(MANIFEST).expect("manifest parses");
    assert_eq!(manifest.package.as_deref(), Some("com.avero.testsample"));
    assert!(manifest
        .components
        .iter()
        .any(|component| component.kind == "provider"));
}

#[test]
fn zip_entry_reads_deflated_manifest() {
    let info = avero::zipscan::scan(APK).expect("zip scan");
    let entry = avero::zipscan::find_entry(&info, "AndroidManifest.xml").expect("manifest entry");
    let bytes = avero::zipscan::read_entry(APK, entry).expect("inflate manifest");
    assert_eq!(bytes.len(), MANIFEST.len());
}
