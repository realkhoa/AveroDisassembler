//! Single-pass hashing + Shannon entropy over a memory-mapped file.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub const CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct FileDigest {
    pub size: u64,
    pub entropy: f64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Hash and measure `data` in one pass (three hashers + byte histogram).
pub fn digest(data: &[u8]) -> FileDigest {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut histogram = [0u64; 256];

    for chunk in data.chunks(CHUNK_SIZE) {
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
        for &byte in chunk {
            histogram[byte as usize] += 1;
        }
    }

    FileDigest {
        size: data.len() as u64,
        entropy: shannon_entropy(&histogram, data.len() as u64),
        md5: hex::encode(md5.finalize()),
        sha1: hex::encode(sha1.finalize()),
        sha256: hex::encode(sha256.finalize()),
    }
}

pub fn shannon_entropy(histogram: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    let mut entropy = 0.0f64;
    for &count in histogram {
        if count > 0 {
            let p = count as f64 / total_f;
            entropy -= p * p.log2();
        }
    }
    (entropy * 1_000_000.0).round() / 1_000_000.0
}

/// Entropy of a byte slice (used for per-section entropy).
pub fn entropy_of(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut histogram = [0u64; 256];
    for &byte in data {
        histogram[byte as usize] += 1;
    }
    shannon_entropy(&histogram, data.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_correct_for_empty() {
        let digest = digest(b"");
        assert_eq!(
            digest.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(digest.size, 0);
        assert_eq!(digest.entropy, 0.0);
    }

    #[test]
    fn hashes_are_correct_for_abc() {
        let digest = digest(b"abc");
        assert_eq!(
            digest.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(digest.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(digest.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy_of(&[0u8; 100]), 0.0);
        assert!(entropy_of(&(0u8..=255).collect::<Vec<_>>()) > 7.9);
    }
}
