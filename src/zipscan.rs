//! Minimal ZIP central-directory reader.
//!
//! Written by hand instead of pulling a ZIP crate: Avero only needs entry names and
//! compression sizes, and this keeps the binary small and the build fast.

#[derive(Debug, Clone, Default)]
pub struct ZipEntryInfo {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub method: u16,
    pub local_offset: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ZipInfo {
    pub entries: Vec<ZipEntryInfo>,
    pub apk_sig_block: bool,
}

const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const CD_SIGNATURE: &[u8; 4] = b"PK\x01\x02";
const APK_SIG_MAGIC: &[u8] = b"APK Sig Block 42";

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn has_apk_sig_block(data: &[u8]) -> bool {
    let tail_start = data.len().saturating_sub(256 * 1024);
    find_subslice(&data[tail_start..], APK_SIG_MAGIC).is_some()
}

/// Parse the central directory. Returns `None` when the data is not a ZIP archive.
pub fn scan(data: &[u8]) -> Option<ZipInfo> {
    if data.len() < 22 {
        return None;
    }
    // EOCD is at the end, optionally followed by a comment (<=65535 bytes).
    let search_start = data.len().saturating_sub(65_535 + 22);
    let mut eocd = None;
    for position in (search_start..=data.len() - 22).rev() {
        if &data[position..position + 4] == EOCD_SIGNATURE {
            eocd = Some(position);
            break;
        }
    }
    let eocd = eocd?;
    let total_entries = u16_at(data, eocd + 10)? as usize;
    let cd_offset = u32_at(data, eocd + 16)? as usize;
    let cd_size = u32_at(data, eocd + 12)? as usize;
    let sig_block = has_apk_sig_block(data);

    // Empty archive (valid ZIP with no entries).
    if total_entries == 0 {
        return Some(ZipInfo {
            entries: Vec::new(),
            apk_sig_block: sig_block,
        });
    }
    // ZIP64: central directory offset is 0xFFFFFFFF and the real values live in the
    // ZIP64 locator. We report the archive but do not enumerate entries.
    if total_entries == 0xFFFF || cd_offset == 0xFFFF_FFFF {
        return Some(ZipInfo {
            entries: Vec::new(),
            apk_sig_block: sig_block,
        });
    }
    if cd_offset >= data.len() || cd_size == 0 {
        return None;
    }

    let mut entries = Vec::with_capacity(total_entries.min(50_000));
    let mut position = cd_offset;
    for _ in 0..total_entries {
        if position + 46 > data.len() || &data[position..position + 4] != CD_SIGNATURE {
            break;
        }
        let method = u16_at(data, position + 10).unwrap_or(0);
        let compressed_size = u32_at(data, position + 20).unwrap_or(0) as u64;
        let uncompressed_size = u32_at(data, position + 24).unwrap_or(0) as u64;
        let name_len = u16_at(data, position + 28).unwrap_or(0) as usize;
        let extra_len = u16_at(data, position + 30).unwrap_or(0) as usize;
        let comment_len = u16_at(data, position + 32).unwrap_or(0) as usize;
        let local_offset = u32_at(data, position + 42).unwrap_or(0);
        let name_start = position + 46;
        let name_end = name_start + name_len;
        if name_end > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();
        entries.push(ZipEntryInfo {
            name,
            compressed_size,
            uncompressed_size,
            method,
            local_offset,
        });
        position = name_end + extra_len + comment_len;
        if entries.len() >= 50_000 {
            break;
        }
    }
    Some(ZipInfo {
        entries,
        apk_sig_block: sig_block,
    })
}

/// Find an entry by name (case-insensitive, as ZIP names are case-preserving).
pub fn find_entry<'a>(info: &'a ZipInfo, name: &str) -> Option<&'a ZipEntryInfo> {
    info.entries
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(name))
}

/// Read and (if needed) inflate one entry. Supports STORED (0) and DEFLATE (8).
pub fn read_entry(data: &[u8], entry: &ZipEntryInfo) -> Option<Vec<u8>> {
    let local = entry.local_offset as usize;
    if data.get(local..local + 4)? != b"PK\x03\x04" {
        return None;
    }
    let name_len = u16_at(data, local + 26)? as usize;
    let extra_len = u16_at(data, local + 28)? as usize;
    let start = local + 30 + name_len + extra_len;
    let end = start.checked_add(entry.compressed_size as usize)?;
    let compressed = data.get(start..end)?;
    match entry.method {
        0 => Some(compressed.to_vec()),
        8 => {
            use std::io::Read;
            let mut output = Vec::with_capacity(entry.uncompressed_size as usize);
            let mut decoder = flate2::read::DeflateDecoder::new(compressed);
            decoder.read_to_end(&mut output).ok()?;
            Some(output)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_a_minimal_zip() {
        // An empty ZIP archive (only an EOCD record).
        let mut data = vec![0u8; 22];
        data[..4].copy_from_slice(EOCD_SIGNATURE);
        let info = scan(&data).expect("empty zip should scan");
        assert!(info.entries.is_empty());
    }

    #[test]
    fn finds_subslice() {
        assert_eq!(find_subslice(b"hello world", b"world"), Some(6));
        assert_eq!(find_subslice(b"hello", b"nope"), None);
    }
}
