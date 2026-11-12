//! Android resource table (`resources.arsc`) parser.
//!
//! Extracts the package name, type/key names and string resource values from the binary
//! resource table. This is a focused parser (not a full `aapt2` replacement): it supports
//! the common `RES_TABLE` → global string pool → package → type/entry layout.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceEntry {
    pub name: String,
    pub value_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ResourceTable {
    pub package: String,
    pub type_count: usize,
    pub entry_count: usize,
    pub strings: Vec<ResourceEntry>,
    pub errors: Vec<String>,
}

const RES_TABLE_TYPE: u16 = 0x0002;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;
const UTF8_FLAG: u32 = 0x100;

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn utf16_string(data: &[u8], offset: usize, length: usize) -> String {
    let mut units = Vec::with_capacity(length);
    for index in 0..length {
        if let Some(value) = u16_at(data, offset + index * 2) {
            units.push(value);
        }
    }
    String::from_utf16_lossy(&units)
}

/// Parse a `ResStringPool` chunk and return its strings.
fn parse_string_pool(data: &[u8], chunk_start: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let Some(header_size) = u16_at(data, chunk_start + 2).map(usize::from) else {
        return strings;
    };
    let Some(string_count) = u32_at(data, chunk_start + 8).map(|value| value as usize) else {
        return strings;
    };
    let Some(flags) = u32_at(data, chunk_start + 16) else {
        return strings;
    };
    let Some(strings_start) = u32_at(data, chunk_start + 20).map(|value| value as usize) else {
        return strings;
    };
    let offsets_start = chunk_start + header_size;
    let data_start = chunk_start + strings_start;
    let utf8 = flags & UTF8_FLAG != 0;
    for index in 0..string_count.min(10_000) {
        let Some(offset) = u32_at(data, offsets_start + index * 4).map(|value| value as usize)
        else {
            break;
        };
        let position = data_start + offset;
        if position >= data.len() {
            break;
        }
        if utf8 {
            // UTF-8 pools store two lengths: UTF-16 code units, then UTF-8 byte length.
            let Some(first) = data.get(position).copied() else {
                break;
            };
            let position = if first & 0x80 != 0 {
                position + 2
            } else {
                position + 1
            };
            let Some(second) = data.get(position).copied() else {
                break;
            };
            let (byte_length, body_start) = if second & 0x80 != 0 {
                let third = data.get(position + 1).copied().unwrap_or(0);
                (
                    (((second & 0x7f) as usize) << 8) | third as usize,
                    position + 2,
                )
            } else {
                (second as usize, position + 1)
            };
            let body_end = body_start.saturating_add(byte_length).min(data.len());
            strings.push(String::from_utf8_lossy(&data[body_start..body_end]).to_string());
        } else {
            let Some(first) = u16_at(data, position) else {
                break;
            };
            let (length, body_start) = if first & 0x8000 != 0 {
                let second = u16_at(data, position + 2).unwrap_or(0);
                (
                    ((((first & 0x7fff) as usize) << 16) | second as usize),
                    position + 4,
                )
            } else {
                (first as usize, position + 2)
            };
            strings.push(utf16_string(data, body_start, length));
        }
    }
    strings
}

/// Parse `resources.arsc`.
pub fn parse(data: &[u8]) -> Option<ResourceTable> {
    if u16_at(data, 0)? != RES_TABLE_TYPE {
        return None;
    }
    let header_size = u16_at(data, 2).map(usize::from)?;
    let table_size = u32_at(data, 4).map(|value| value as usize)?;
    let mut table = ResourceTable::default();
    let end = table_size.min(data.len());
    let mut global_strings: Vec<String> = Vec::new();
    let mut position = header_size;
    while position + 8 <= end {
        let chunk_type = u16_at(data, position)?;
        let chunk_header_size = u16_at(data, position + 2).map(usize::from)?;
        let chunk_size = u32_at(data, position + 4).map(|value| value as usize)?;
        if chunk_size < 8 {
            break;
        }
        let chunk_end = (position + chunk_size).min(data.len());
        match chunk_type {
            RES_STRING_POOL_TYPE => {
                if global_strings.is_empty() {
                    global_strings = parse_string_pool(data, position);
                }
            }
            RES_TABLE_PACKAGE_TYPE => {
                parse_package(
                    data,
                    position,
                    chunk_header_size,
                    chunk_size,
                    &global_strings,
                    &mut table,
                );
            }
            _ => {}
        }
        position = chunk_end;
    }
    Some(table)
}

fn parse_package(
    data: &[u8],
    package_start: usize,
    header_size: usize,
    chunk_size: usize,
    global_strings: &[String],
    table: &mut ResourceTable,
) {
    let Some(package_id) = u32_at(data, package_start + 8) else {
        table.errors.push("package missing id".to_string());
        return;
    };
    let _ = package_id;
    let name_length = 128usize;
    let mut name_units = Vec::new();
    for index in 0..name_length {
        match u16_at(data, package_start + 12 + index * 2) {
            Some(0) | None => break,
            Some(value) => name_units.push(value),
        }
    }
    table.package = String::from_utf16_lossy(&name_units);
    let Some(type_strings_offset) = u32_at(data, package_start + 268).map(|value| value as usize)
    else {
        table
            .errors
            .push("package missing type strings".to_string());
        return;
    };
    let Some(key_strings_offset) = u32_at(data, package_start + 276).map(|value| value as usize)
    else {
        table.errors.push("package missing key strings".to_string());
        return;
    };
    let type_strings = parse_string_pool(data, package_start + type_strings_offset);
    let key_strings = parse_string_pool(data, package_start + key_strings_offset);
    table.type_count = type_strings.len();

    let package_end = (package_start + chunk_size).min(data.len());
    let mut position = package_start + header_size;
    while position + 8 <= package_end {
        let Some(chunk_type) = u16_at(data, position) else {
            break;
        };
        let Some(type_header_size) = u16_at(data, position + 2).map(usize::from) else {
            break;
        };
        let Some(type_chunk_size) = u32_at(data, position + 4).map(|value| value as usize) else {
            break;
        };
        if type_chunk_size < 8 {
            break;
        }
        let chunk_end = (position + type_chunk_size).min(data.len());
        match chunk_type {
            RES_TABLE_TYPE_TYPE => {
                parse_type_chunk(
                    data,
                    position,
                    type_header_size,
                    &type_strings,
                    &key_strings,
                    global_strings,
                    table,
                );
            }
            RES_TABLE_TYPE_SPEC_TYPE => {}
            _ => {}
        }
        position = chunk_end;
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_type_chunk(
    data: &[u8],
    chunk_start: usize,
    header_size: usize,
    type_strings: &[String],
    key_strings: &[String],
    global_strings: &[String],
    table: &mut ResourceTable,
) {
    let Some(type_id) = data.get(chunk_start + 8).copied() else {
        return;
    };
    let Some(entry_count) = u32_at(data, chunk_start + 12).map(|value| value as usize) else {
        return;
    };
    let Some(entries_start) = u32_at(data, chunk_start + 16).map(|value| value as usize) else {
        return;
    };
    let type_name = type_id
        .checked_sub(1)
        .and_then(|index| type_strings.get(index as usize))
        .cloned()
        .unwrap_or_else(|| format!("type_{type_id}"));
    let offsets_start = chunk_start + header_size;
    for index in 0..entry_count.min(4096) {
        let Some(offset) = u32_at(data, offsets_start + index * 4).map(|value| value as usize)
        else {
            break;
        };
        if offset == 0xffff_ffff {
            continue;
        }
        let entry_start = chunk_start + entries_start + offset;
        let Some(_entry_size) = u16_at(data, entry_start) else {
            continue;
        };
        let Some(key_index) = u32_at(data, entry_start + 4).map(|value| value as usize) else {
            continue;
        };
        let value_offset = entry_start + 8;
        let Some(value_type) = data.get(value_offset + 3).copied() else {
            continue;
        };
        let Some(data_value) = u32_at(data, value_offset + 4) else {
            continue;
        };
        let key_name = key_strings
            .get(key_index)
            .cloned()
            .unwrap_or_else(|| format!("key_{key_index}"));
        let (value_type_name, value) = match value_type {
            0x03 => (
                "string".to_string(),
                global_strings
                    .get(data_value as usize)
                    .cloned()
                    .unwrap_or_default(),
            ),
            0x01 => ("reference".to_string(), format!("@0x{data_value:08x}")),
            0x10 => ("int".to_string(), (data_value as i32).to_string()),
            0x11 => ("hex".to_string(), format!("0x{data_value:08x}")),
            0x12 => ("bool".to_string(), (data_value != 0).to_string()),
            other => (
                "value".to_string(),
                format!("type 0x{other:02x} data 0x{data_value:x}"),
            ),
        };
        table.entry_count += 1;
        if value_type_name == "string" && table.strings.len() < 200 {
            table.strings.push(ResourceEntry {
                name: format!("{type_name}/{key_name}"),
                value_type: value_type_name,
                value,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zipscan;

    const RES_APK: &[u8] = include_bytes!("../tests/fixtures/sample-res.apk");

    #[test]
    fn parses_resources_from_apk() {
        let info = zipscan::scan(RES_APK).expect("zip");
        let entry = zipscan::find_entry(&info, "resources.arsc").expect("resources.arsc");
        let data = zipscan::read_entry(RES_APK, entry).expect("read resources.arsc");
        let table = parse(&data).expect("resource table");
        assert_eq!(table.package, "com.avero.signed");
        assert!(table.entry_count >= 1, "entries: {}", table.entry_count);
        let app_name = table
            .strings
            .iter()
            .find(|entry| entry.name.contains("app_name"))
            .expect("app_name resource");
        assert_eq!(app_name.value, "Avero Signed Sample");
        let note = table
            .strings
            .iter()
            .find(|entry| entry.name.contains("fixture_note"))
            .expect("fixture_note resource");
        assert_eq!(note.value, "fixture-string-value-42");
    }

    #[test]
    fn rejects_non_resource_data() {
        assert!(parse(b"not an arsc file").is_none());
    }
}
