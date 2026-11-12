//! APK signature parsing (v1 JAR signatures, v2/v3 APK Signature Scheme block).
//!
//! v2/v3 certificate chains are extracted from the APK Signing Block and parsed with
//! `x509-parser`. v1 is detected from `META-INF/*.(RSA|DSA|EC)` entries (full PKCS#7
//! parsing is out of scope for now).

use serde::Serialize;

use crate::hashing;
use crate::zipscan;

pub const APK_SIG_MAGIC: &[u8] = b"APK Sig Block 42";
pub const V2_BLOCK_ID: u32 = 0x7109_871a;
pub const V3_BLOCK_ID: u32 = 0xf053_68c0;
pub const V31_BLOCK_ID: u32 = 0x1b93_ad61;

#[derive(Debug, Clone, Serialize, Default)]
pub struct SignerCertificate {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub sha256: String,
    pub self_signed: bool,
    pub debug_certificate: bool,
    pub expired: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ApkSignature {
    pub schemes: Vec<String>,
    pub signers: Vec<SignerCertificate>,
    pub v1_entries: usize,
    pub errors: Vec<String>,
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8).map(|bytes| {
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        u64::from_le_bytes(array)
    })
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn parse_certificate(der: &[u8]) -> Option<SignerCertificate> {
    use x509_parser::prelude::*;
    let (_, certificate) = X509Certificate::from_der(der).ok()?;
    let subject = certificate.subject().to_string();
    let issuer = certificate.issuer().to_string();
    let validity = certificate.validity();
    let not_before_unix = validity.not_before.timestamp();
    let not_after_unix = validity.not_after.timestamp();
    Some(SignerCertificate {
        subject: subject.clone(),
        issuer: issuer.clone(),
        serial: certificate.raw_serial_as_string(),
        not_before: validity.not_before.to_string(),
        not_after: validity.not_after.to_string(),
        sha256: hashing::digest(der).sha256,
        self_signed: subject == issuer,
        debug_certificate: subject.contains("Android Debug")
            || subject.contains("CN=Android Debug"),
        expired: now_unix() > not_after_unix && not_after_unix > not_before_unix,
    })
}

/// Parse a v2/v3 scheme value: length-prefixed signers, each with signed data containing
/// the certificate chain.
fn parse_scheme_value(value: &[u8]) -> Vec<SignerCertificate> {
    let mut certificates = Vec::new();
    let Some(signers_len) = u32_at(value, 0) else {
        return certificates;
    };
    let signers_end = 4usize.saturating_add(signers_len as usize).min(value.len());
    let mut position = 4usize;
    while position + 4 <= signers_end {
        let Some(signer_len) = u32_at(value, position) else {
            break;
        };
        position += 4;
        let signer_end = position
            .saturating_add(signer_len as usize)
            .min(value.len());
        // signed data
        if position + 4 > signer_end {
            break;
        }
        let Some(signed_data_len) = u32_at(value, position) else {
            break;
        };
        position += 4;
        let signed_data_start = position;
        let signed_data_end = position
            .saturating_add(signed_data_len as usize)
            .min(value.len());
        let mut cursor = signed_data_start;
        if let Some(digests_len) = u32_at(value, cursor) {
            cursor = cursor.saturating_add(4 + digests_len as usize);
            if let Some(certificates_len) = u32_at(value, cursor) {
                cursor += 4;
                let certificates_end = cursor
                    .saturating_add(certificates_len as usize)
                    .min(value.len());
                while cursor + 4 <= certificates_end {
                    let Some(certificate_len) = u32_at(value, cursor) else {
                        break;
                    };
                    cursor += 4;
                    let certificate_end = cursor.saturating_add(certificate_len as usize);
                    if certificate_end > value.len() {
                        break;
                    }
                    if let Some(certificate) = parse_certificate(&value[cursor..certificate_end]) {
                        certificates.push(certificate);
                    }
                    cursor = certificate_end;
                }
            }
        }
        position = signer_end.max(signed_data_end).max(position);
    }
    certificates
}

/// Parse the APK Signing Block, returning (schemes, signers, errors).
fn parse_signing_block(data: &[u8]) -> (Vec<String>, Vec<SignerCertificate>, Vec<String>) {
    let mut schemes = Vec::new();
    let mut signers = Vec::new();
    let mut errors = Vec::new();
    let Some(magic_position) = zipscan::find_subslice(data, APK_SIG_MAGIC) else {
        return (schemes, signers, errors);
    };
    let block_end = magic_position + APK_SIG_MAGIC.len();
    if block_end < 24 {
        errors.push("APK Signing Block too short".to_string());
        return (schemes, signers, errors);
    }
    let Some(second_size) = u64_at(data, block_end - 24) else {
        errors.push("cannot read APK Signing Block size".to_string());
        return (schemes, signers, errors);
    };
    let total = second_size as usize + 8;
    if total > block_end {
        errors.push("APK Signing Block size exceeds file".to_string());
        return (schemes, signers, errors);
    }
    let block_start = block_end - total;
    let Some(first_size) = u64_at(data, block_start) else {
        errors.push("cannot read APK Signing Block header".to_string());
        return (schemes, signers, errors);
    };
    if first_size != second_size {
        errors.push("APK Signing Block size mismatch".to_string());
        return (schemes, signers, errors);
    }
    let pairs_start = block_start + 8;
    let pairs_end = block_end - 24;
    let mut position = pairs_start;
    while position + 12 <= pairs_end {
        let Some(pair_len) = u64_at(data, position) else {
            break;
        };
        let pair_end = position.saturating_add(8 + pair_len as usize);
        if pair_end > pairs_end || pair_len < 4 {
            errors.push("malformed APK Signing Block pair".to_string());
            break;
        }
        let Some(block_id) = u32_at(data, position + 8) else {
            break;
        };
        let value = &data[position + 12..pair_end];
        match block_id {
            V2_BLOCK_ID => {
                schemes.push("v2".to_string());
                signers.extend(parse_scheme_value(value));
            }
            V3_BLOCK_ID => {
                schemes.push("v3".to_string());
                signers.extend(parse_scheme_value(value));
            }
            V31_BLOCK_ID => {
                schemes.push("v3.1".to_string());
                signers.extend(parse_scheme_value(value));
            }
            _ => {}
        }
        position = pair_end;
    }
    (schemes, signers, errors)
}

/// Parse all signature information from an APK and its ZIP index.
pub fn parse_apk(data: &[u8], info: &zipscan::ZipInfo) -> ApkSignature {
    let mut signature = ApkSignature::default();
    signature.v1_entries = info
        .entries
        .iter()
        .filter(|entry| {
            let upper = entry.name.to_ascii_uppercase();
            upper.starts_with("META-INF/")
                && (upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC"))
        })
        .count();
    if signature.v1_entries > 0 {
        signature.schemes.push("v1".to_string());
    }
    let (schemes, signers, errors) = parse_signing_block(data);
    for scheme in schemes {
        if !signature.schemes.contains(&scheme) {
            signature.schemes.push(scheme);
        }
    }
    signature.signers = signers;
    signature.errors = errors;
    // v2/v3 (and v3.1) repeat the same certificate chain; keep one entry per certificate.
    let mut seen = std::collections::BTreeSet::new();
    signature.signers = signature
        .signers
        .into_iter()
        .filter(|signer| seen.insert(signer.sha256.clone()))
        .collect();
    signature
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED_APK: &[u8] = include_bytes!("../tests/fixtures/sample-signed.apk");

    #[test]
    fn parses_v2_v3_certificate() {
        let info = zipscan::scan(SIGNED_APK).expect("zip");
        let signature = parse_apk(SIGNED_APK, &info);
        assert!(
            signature.schemes.iter().any(|scheme| scheme == "v2"),
            "schemes: {:?}",
            signature.schemes
        );
        assert!(
            signature.schemes.iter().any(|scheme| scheme == "v3"),
            "schemes: {:?}",
            signature.schemes
        );
        assert!(!signature.signers.is_empty());
        let signer = &signature.signers[0];
        assert!(signer.subject.contains("Avero Test Cert"));
        assert!(!signer.sha256.is_empty());
        assert!(!signer.expired);
    }

    #[test]
    fn unsigned_apk_has_no_signature() {
        const UNSIGNED: &[u8] = include_bytes!("../tests/fixtures/sample.apk");
        let info = zipscan::scan(UNSIGNED).expect("zip");
        let signature = parse_apk(UNSIGNED, &info);
        assert!(signature.schemes.is_empty());
        assert!(signature.signers.is_empty());
    }
}
