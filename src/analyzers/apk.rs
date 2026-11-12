//! APK analyzer: ZIP structure + binary `AndroidManifest.xml` (AXML) triage.
//!
//! Parses the real manifest (package, version, SDK levels, permissions, application flags,
//! components with exported/permission) without jadx/apktool. Code decompilation is still
//! delegated to sidecars in later phases.

use std::collections::BTreeSet;

use serde_json::json;

use crate::analyzers::{AnalysisContext, Analyzer, Fragment};
use crate::apksig;
use crate::arsc;
use crate::axml;
use crate::evidence::{loc, make_evidence};
use crate::findings::make_finding;
use crate::ir::{Artifact, Kind, Severity};
use crate::zipscan;

const ENGINE: &str = "avero.apk";

/// Permissions that grant access to sensitive data or capabilities on modern Android.
const DANGEROUS_PERMISSIONS: &[&str] = &[
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.QUERY_ALL_PACKAGES",
];

fn is_dangerous_permission(permission: &str) -> bool {
    DANGEROUS_PERMISSIONS
        .iter()
        .any(|dangerous| permission.eq_ignore_ascii_case(dangerous))
}

pub struct ApkAnalyzer;

impl Analyzer for ApkAnalyzer {
    fn id(&self) -> &'static str {
        "apk.structure"
    }

    fn accepts(&self, artifact: &Artifact) -> bool {
        artifact.has_kind(Kind::Apk)
    }

    fn priority(&self) -> i32 {
        12
    }

    fn run(&self, ctx: &AnalysisContext, _artifact: &Artifact) -> Fragment {
        let mut fragment = Fragment::default();
        let Some(info) = zipscan::scan(ctx.data) else {
            fragment
                .warnings
                .push("apk.structure: could not read ZIP central directory".to_string());
            return fragment;
        };
        let names: Vec<&str> = info
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        let lower: Vec<String> = names.iter().map(|name| name.to_ascii_lowercase()).collect();
        let dex_files: Vec<&str> = names
            .iter()
            .copied()
            .filter(|name| name.to_ascii_lowercase().ends_with(".dex"))
            .collect();
        let mut abis: BTreeSet<String> = BTreeSet::new();
        for name in &names {
            let parts: Vec<&str> = name.split('/').collect();
            if parts.len() >= 3 && parts[0].eq_ignore_ascii_case("lib") {
                abis.insert(parts[1].to_string());
            }
        }
        let assets = names
            .iter()
            .filter(|name| name.starts_with("assets/") && !name.ends_with('/'))
            .count();
        let resources = names
            .iter()
            .filter(|name| name.starts_with("res/") && !name.ends_with('/'))
            .count();
        let signature = apksig::parse_apk(ctx.data, &info);
        let signing_v1 = signature.v1_entries > 0;
        let signing_v2 = signature
            .schemes
            .iter()
            .any(|scheme| matches!(scheme.as_str(), "v2" | "v3" | "v3.1"));
        let resource_table = zipscan::find_entry(&info, "resources.arsc")
            .and_then(|entry| zipscan::read_entry(ctx.data, entry))
            .and_then(|bytes| arsc::parse(&bytes));
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
        let has_manifest = lower.iter().any(|name| name == "androidmanifest.xml");
        let has_resources_arsc = names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("resources.arsc"));

        fragment.facts.insert("entries".into(), json!(names.len()));
        fragment
            .facts
            .insert("dex_count".into(), json!(dex_files.len()));
        fragment.facts.insert(
            "dex_files".into(),
            json!(dex_files.iter().take(10).collect::<Vec<_>>()),
        );
        fragment
            .facts
            .insert("native_abis".into(), json!(abis.iter().collect::<Vec<_>>()));
        fragment.facts.insert("assets_count".into(), json!(assets));
        fragment
            .facts
            .insert("resources_count".into(), json!(resources));
        fragment
            .facts
            .insert("signing_v1".into(), json!(signing_v1));
        fragment
            .facts
            .insert("signing_v2_or_v3".into(), json!(signing_v2));
        fragment
            .facts
            .insert("apk_signature_schemes".into(), json!(signature.schemes));
        fragment
            .facts
            .insert("apk_signers".into(), json!(signature.signers));
        if let Some(table) = &resource_table {
            fragment.facts.insert("apk_resources".into(), json!(table));
            fragment
                .facts
                .insert("apk_resource_package".into(), json!(table.package));
        }
        fragment
            .facts
            .insert("compression_ratio".into(), json!(ratio));
        fragment
            .facts
            .insert("has_android_manifest".into(), json!(has_manifest));
        fragment
            .facts
            .insert("has_resources_arsc".into(), json!(has_resources_arsc));
        fragment
            .metadata
            .insert("apk_entries".into(), json!(names.len()));
        fragment
            .metadata
            .insert("apk_dex_count".into(), json!(dex_files.len()));
        fragment.metadata.insert(
            "apk_native_abis".into(),
            json!(abis.iter().collect::<Vec<_>>()),
        );
        fragment
            .metadata
            .insert("apk_signed_v1".into(), json!(signing_v1));
        fragment
            .metadata
            .insert("apk_signature_schemes".into(), json!(signature.schemes));
        fragment
            .metadata
            .insert("apk_signer_count".into(), json!(signature.signers.len()));

        // ---- AndroidManifest.xml (AXML) ----------------------------------
        let manifest_entry = zipscan::find_entry(&info, "AndroidManifest.xml");
        let mut parsed_manifest: Option<axml::AxmlManifest> = None;
        if let Some(entry) = manifest_entry {
            match zipscan::read_entry(ctx.data, entry) {
                Some(bytes) => match axml::parse_manifest(&bytes) {
                    Ok(manifest) => parsed_manifest = Some(manifest),
                    Err(error) => fragment
                        .warnings
                        .push(format!("apk.structure: AXML parse failed: {error}")),
                },
                None => fragment.warnings.push(
                    "apk.structure: could not read AndroidManifest.xml (compression method?)"
                        .to_string(),
                ),
            }
        }
        let mut manifest_evidence = None;
        if let Some(manifest) = &parsed_manifest {
            let package = manifest.package.clone().unwrap_or_default();
            let exported_components: Vec<String> = manifest
                .components
                .iter()
                .filter(|component| component.is_exported_without_permission())
                .map(|component| format!("{}:{}", component.kind, component.name))
                .collect();
            let dangerous: Vec<String> = manifest
                .permissions
                .iter()
                .filter(|permission| is_dangerous_permission(permission))
                .cloned()
                .collect();
            fragment.facts.insert("manifest_parsed".into(), json!(true));
            fragment
                .facts
                .insert("apk_package".into(), json!(manifest.package));
            fragment
                .facts
                .insert("apk_version_code".into(), json!(manifest.version_code));
            fragment
                .facts
                .insert("apk_version_name".into(), json!(manifest.version_name));
            fragment
                .facts
                .insert("apk_min_sdk".into(), json!(manifest.min_sdk));
            fragment
                .facts
                .insert("apk_target_sdk".into(), json!(manifest.target_sdk));
            fragment
                .facts
                .insert("apk_debuggable".into(), json!(manifest.debuggable));
            fragment
                .facts
                .insert("apk_allow_backup".into(), json!(manifest.allow_backup));
            fragment
                .facts
                .insert("apk_permissions".into(), json!(manifest.permissions));
            fragment
                .facts
                .insert("apk_dangerous_permissions".into(), json!(dangerous));
            fragment.facts.insert(
                "apk_component_count".into(),
                json!(manifest.components.len()),
            );
            fragment
                .facts
                .insert("apk_exported_components".into(), json!(exported_components));
            fragment.facts.insert(
                "apk_components".into(),
                json!(manifest
                    .components
                    .iter()
                    .map(|component| json!({
                        "kind": component.kind,
                        "name": component.name,
                        "exported": component.exported,
                        "permission": component.permission,
                    }))
                    .collect::<Vec<_>>()),
            );

            fragment.metadata.insert(
                "apk_package".into(),
                json!(manifest.package.clone().unwrap_or_default()),
            );
            fragment.metadata.insert(
                "apk_version_code".into(),
                json!(manifest.version_code.unwrap_or(0)),
            );
            fragment.metadata.insert(
                "apk_version_name".into(),
                json!(manifest.version_name.clone().unwrap_or_default()),
            );
            fragment
                .metadata
                .insert("apk_min_sdk".into(), json!(manifest.min_sdk));
            fragment
                .metadata
                .insert("apk_target_sdk".into(), json!(manifest.target_sdk));
            fragment
                .metadata
                .insert("apk_debuggable".into(), json!(manifest.debuggable));

            let evidence = make_evidence(
                ENGINE,
                env!("CARGO_PKG_VERSION"),
                "metadata",
                loc(vec![
                    ("package", json!(package)),
                    ("version_code", json!(manifest.version_code)),
                    ("min_sdk", json!(manifest.min_sdk)),
                    ("target_sdk", json!(manifest.target_sdk)),
                ]),
                Some(format!(
                    "package={package} versionCode={} minSdk={} targetSdk={} permissions={} components={}",
                    manifest.version_code.unwrap_or(0),
                    manifest.min_sdk.unwrap_or(0),
                    manifest.target_sdk.unwrap_or(0),
                    manifest.permissions.len(),
                    manifest.components.len()
                )),
                1.0,
                Vec::new(),
            );

            if manifest.debuggable {
                fragment.findings.push(make_finding(
                    Severity::High,
                    "android",
                    "APK debuggable=true",
                    "Manifest enables android:debuggable=\"true\" — allows a debugger to attach to the process, "
                        .to_string()
                        + "usually absent from official releases and a sign of a test build/re-pack.",
                    &[&evidence],
                    0.9,
                    Some("Disable debuggable before release.".to_string()),
                ));
            }
            if !exported_components.is_empty() {
                fragment.findings.push(make_finding(
                    Severity::Medium,
                    "android",
                    format!(
                        "{} exported component(s) without permission",
                        exported_components.len()
                    ),
                    format!(
                        "Components with exported=true but no android:permission declared: {}. \
                         Other apps can call them directly — review intent handling.",
                        exported_components
                            .iter()
                            .take(10)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    &[&evidence],
                    0.7,
                    None,
                ));
            }
            if !dangerous.is_empty() {
                fragment.findings.push(make_finding(
                    Severity::Low,
                    "android",
                    format!("Dangerous permissions ({})", dangerous.len()),
                    format!(
                        "APK requests sensitive permissions: {}. Cross-check against the app's actual functionality.",
                        dangerous.join(", ")
                    ),
                    &[&evidence],
                    0.8,
                    None,
                ));
            }
            if manifest.allow_backup == Some(true) {
                fragment.findings.push(make_finding(
                    Severity::Low,
                    "android",
                    "allowBackup=true",
                    "Manifest allows app data backup over adb — can expose sensitive data."
                        .to_string(),
                    &[&evidence],
                    0.7,
                    None,
                ));
            }
            fragment.evidence.push(evidence.clone());
            manifest_evidence = Some(evidence);
        }
        let _ = manifest_evidence;

        let evidence = make_evidence(
            ENGINE,
            env!("CARGO_PKG_VERSION"),
            "metadata",
            loc(vec![
                ("entries", json!(names.len())),
                ("dex", json!(dex_files.len())),
            ]),
            Some(format!(
                "APK with {} entries, {} dex, ABIs={}, v1_sig={}, v2_sig={}",
                names.len(),
                dex_files.len(),
                abis.iter().cloned().collect::<Vec<_>>().join(","),
                signing_v1,
                signing_v2
            )),
            1.0,
            Vec::new(),
        );

        if signature.schemes.is_empty() {
            fragment.findings.push(make_finding(
                Severity::Medium,
                "android",
                "APK is not signed (no v1/v2/v3 signature found)",
                "No META-INF signature or APK Signing Block found. An unsigned APK cannot be installed on a real device (unless bypassed) and may have been re-packed."
                    .to_string(),
                &[&evidence],
                0.8,
                None,
            ));
        } else if signing_v1 && !signing_v2 {
            fragment.findings.push(make_finding(
                Severity::Low,
                "android",
                "APK is signed with v1 (JAR) only",
                "Only the legacy v1 JAR signature was found. Android 7.0+ supports APK Signature Scheme v2/v3, which protects the whole file and is required by newer target SDK levels."
                    .to_string(),
                &[&evidence],
                0.6,
                Some("Re-sign with v2/v3 enabled (apksigner defaults to both).".to_string()),
            ));
        }
        for signer in &signature.signers {
            if signer.debug_certificate {
                fragment.findings.push(make_finding(
                    Severity::Medium,
                    "android",
                    "APK is signed with a debug certificate",
                    format!(
                        "Signer subject '{}' looks like the Android debug keystore (CN=Android Debug). Debug-signed builds are not release builds and cannot be updated by the official distributor.",
                        signer.subject
                    ),
                    &[&evidence],
                    0.8,
                    None,
                ));
                break;
            }
        }
        if signature.signers.iter().any(|signer| signer.expired) {
            fragment.findings.push(make_finding(
                Severity::Medium,
                "android",
                "APK signing certificate is expired",
                "At least one signer certificate is outside its validity period. Android still installs such APKs in many cases, but it indicates a stale signing key or a re-pack."
                    .to_string(),
                &[&evidence],
                0.7,
                None,
            ));
        }
        if signature.signers.iter().any(|signer| signer.self_signed) {
            fragment.findings.push(make_finding(
                Severity::Info,
                "android",
                "APK signing certificate is self-signed",
                "The signer certificate is self-signed. This is normal for Android (no public CA chain), but it means the signer identity is only meaningful if the certificate is known from a previous version."
                    .to_string(),
                &[&evidence],
                0.5,
                None,
            ));
        }
        if dex_files.len() > 1 {
            fragment.findings.push(make_finding(
                Severity::Info,
                "android",
                format!("Multidex ({} dex)", dex_files.len()),
                "APK contains multiple classes*.dex files — a large app or code that was added."
                    .to_string(),
                &[&evidence],
                0.9,
                None,
            ));
        }
        if !abis.is_empty() {
            fragment.findings.push(make_finding(
                Severity::Info,
                "android",
                format!(
                    "Native libraries: {}",
                    abis.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                format!(
                    "APK bundles native .so for ABIs: {}. Native code often holds protected/obfuscated logic.",
                    abis.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                &[&evidence],
                0.9,
                None,
            ));
        }
        if ratio > 100.0 {
            fragment.findings.push(make_finding(
                Severity::Low,
                "android",
                format!("Unusual compression ratio ({ratio}x)"),
                "Uncompressed/compressed ratio is very high — may contain large compressed data; watch for zip bombs when extracting."
                    .to_string(),
                &[&evidence],
                0.5,
                None,
            ));
        }
        fragment.evidence.push(evidence);
        if parsed_manifest.is_none() {
            fragment.unknowns.push(
                "AndroidManifest binary XML (AXML) could not be parsed — needs a jadx/apktool adapter"
                    .to_string(),
            );
        }
        fragment
    }
}
