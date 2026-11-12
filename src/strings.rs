//! String extraction: ASCII and UTF-16LE, with section mapping.

use crate::ir::{Section, StringEntry};
use crate::util::is_printable_ascii;

/// Extract printable ASCII runs of at least `min_len` characters.
pub fn extract_ascii(
    data: &[u8],
    min_len: usize,
    limit: usize,
    base_offset: u64,
) -> Vec<StringEntry> {
    let mut entries = Vec::new();
    let mut start: Option<usize> = None;
    for (index, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            if start.is_none() {
                start = Some(index);
            }
        } else if let Some(run_start) = start.take() {
            if index - run_start >= min_len {
                entries.push(StringEntry {
                    offset: base_offset + run_start as u64,
                    value: String::from_utf8_lossy(&data[run_start..index]).to_string(),
                    encoding: "ascii".to_string(),
                    section: None,
                });
                if entries.len() >= limit {
                    return entries;
                }
            }
        }
    }
    if let Some(run_start) = start {
        if data.len() - run_start >= min_len {
            entries.push(StringEntry {
                offset: base_offset + run_start as u64,
                value: String::from_utf8_lossy(&data[run_start..]).to_string(),
                encoding: "ascii".to_string(),
                section: None,
            });
        }
    }
    entries
}

/// Extract UTF-16LE runs (ASCII-only characters, as produced by Windows `L""` literals).
pub fn extract_utf16le(
    data: &[u8],
    min_len: usize,
    limit: usize,
    base_offset: u64,
) -> Vec<StringEntry> {
    let mut entries = Vec::new();
    let mut index = 0usize;
    while index + 1 < data.len() {
        let start = index;
        let mut chars = String::new();
        while index + 1 < data.len() && data[index + 1] == 0 && is_printable_ascii(data[index]) {
            chars.push(data[index] as char);
            index += 2;
        }
        if chars.len() >= min_len {
            entries.push(StringEntry {
                offset: base_offset + start as u64,
                value: chars,
                encoding: "utf16le".to_string(),
                section: None,
            });
            if entries.len() >= limit {
                return entries;
            }
        }
        index = index.max(start + 1);
    }
    entries
}

/// Map a file offset to a section name when section layout is known.
pub fn section_for_offset(offset: u64, sections: &[Section]) -> Option<String> {
    for section in sections {
        if section.raw_size > 0
            && offset >= section.raw_offset
            && offset < section.raw_offset + section.raw_size
        {
            return Some(section.name.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ascii_strings() {
        let data = b"\x00\x01hello world\x00hi\x00long enough string\xff";
        let values: Vec<String> = extract_ascii(data, 6, 100, 0)
            .into_iter()
            .map(|entry| entry.value)
            .collect();
        assert!(values.iter().any(|value| value == "hello world"));
        assert!(values.iter().any(|value| value == "long enough string"));
        assert!(!values.iter().any(|value| value == "hi"));
    }

    #[test]
    fn respects_limit() {
        let data = b"aaaaaa\x00bbbbbb\x00cccccc\x00";
        let entries = extract_ascii(data, 6, 2, 0);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn extracts_utf16le_strings() {
        let mut data = vec![0u8];
        for unit in "AveroReverse".encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        data.extend_from_slice(&[0, 0]);
        let values: Vec<String> = extract_utf16le(&data, 6, 100, 0)
            .into_iter()
            .map(|entry| entry.value)
            .collect();
        assert!(values.iter().any(|value| value == "AveroReverse"));
    }

    #[test]
    fn maps_offsets_to_sections() {
        let sections = vec![Section {
            name: ".text".into(),
            va: 0x1000,
            vsize: 0x200,
            raw_offset: 0x400,
            raw_size: 0x200,
            entropy: 0.0,
            flags: vec![],
        }];
        assert_eq!(
            section_for_offset(0x500, &sections).as_deref(),
            Some(".text")
        );
        assert_eq!(section_for_offset(0x900, &sections), None);
    }
}
