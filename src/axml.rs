//! Android binary XML (AXML) parser — reads `AndroidManifest.xml` straight from an APK.
//!
//! Implemented from the AOSP `ResourceTypes.h` chunk format; no external tools, no Python.
//! Supports UTF-8 and UTF-16 string pools, typed attribute values and the manifest subset
//! Avero needs for triage (package, SDK levels, permissions, application flags,
//! components with exported/permission).

use serde::Serialize;

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;

const TYPE_REFERENCE: u8 = 0x01;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;

const NO_INDEX: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value")]
pub enum AttrValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Ref(u32),
    Unknown,
}

impl AttrValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AttrValue::Str(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            AttrValue::Int(value) => Some(*value),
            AttrValue::Ref(value) => Some(*value as i64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            AttrValue::Bool(value) => Some(*value),
            AttrValue::Int(value) => Some(*value != 0),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Component {
    pub kind: String,
    pub name: String,
    pub exported: Option<bool>,
    pub permission: Option<String>,
}

impl Component {
    pub fn is_exported_without_permission(&self) -> bool {
        self.exported == Some(true) && self.permission.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AxmlManifest {
    pub package: Option<String>,
    pub version_code: Option<i64>,
    pub version_name: Option<String>,
    pub min_sdk: Option<i64>,
    pub target_sdk: Option<i64>,
    pub permissions: Vec<String>,
    pub debuggable: bool,
    pub allow_backup: Option<bool>,
    pub components: Vec<Component>,
    pub element_count: usize,
    pub parsed: bool,
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_utf8_length(data: &[u8], position: &mut usize) -> Result<usize, String> {
    let first = *data.get(*position).ok_or("truncated UTF-8 length")?;
    *position += 1;
    if first & 0x80 != 0 {
        let second = *data.get(*position).ok_or("truncated UTF-8 length (2)")?;
        *position += 1;
        Ok((((first & 0x7F) as usize) << 8) | second as usize)
    } else {
        Ok(first as usize)
    }
}

fn decode_utf8_string(data: &[u8], start: usize) -> Result<String, String> {
    let mut position = start;
    let _char_count = read_utf8_length(data, &mut position)?;
    let byte_length = read_utf8_length(data, &mut position)?;
    let end = position
        .checked_add(byte_length)
        .ok_or("string length overflow")?;
    let bytes = data
        .get(position..end)
        .ok_or("truncated UTF-8 string data")?;
    Ok(String::from_utf8_lossy(bytes).to_string())
}

fn decode_utf16_string(data: &[u8], start: usize) -> Result<String, String> {
    let mut position = start;
    let first = u16_at(data, position).ok_or("truncated UTF-16 length")?;
    position += 2;
    let length = if first & 0x8000 != 0 {
        let second = u16_at(data, position).ok_or("truncated UTF-16 length (2)")?;
        position += 2;
        (((first & 0x7FFF) as usize) << 16) | second as usize
    } else {
        first as usize
    };
    let mut units = Vec::with_capacity(length);
    for index in 0..length {
        let unit = u16_at(data, position + index * 2).ok_or("truncated UTF-16 data")?;
        units.push(unit);
    }
    Ok(String::from_utf16_lossy(&units))
}

fn parse_string_pool(chunk: &[u8]) -> Result<Vec<String>, String> {
    let header_size = u16_at(chunk, 2).ok_or("bad string pool header")? as usize;
    let string_count = u32_at(chunk, 8).ok_or("bad string count")? as usize;
    let flags = u32_at(chunk, 16).ok_or("bad string flags")?;
    let strings_start = u32_at(chunk, 20).ok_or("bad string start")? as usize;
    let utf8 = flags & 0x100 != 0;

    let offsets_end = header_size
        .checked_add(string_count * 4)
        .ok_or("string pool overflow")?;
    if offsets_end > chunk.len() {
        return Err("string pool offsets out of bounds".to_string());
    }
    let mut strings = Vec::with_capacity(string_count);
    for index in 0..string_count {
        let offset = u32_at(chunk, header_size + index * 4).ok_or("bad string offset")? as usize;
        let start = strings_start
            .checked_add(offset)
            .ok_or("string offset overflow")?;
        let value = if utf8 {
            decode_utf8_string(chunk, start)?
        } else {
            decode_utf16_string(chunk, start)?
        };
        strings.push(value);
    }
    Ok(strings)
}

fn pool_get(pool: &[String], index: u32) -> Option<&str> {
    if index == NO_INDEX {
        return None;
    }
    pool.get(index as usize).map(String::as_str)
}

#[derive(Debug, Clone)]
struct Attribute {
    name: String,
    value: AttrValue,
}

impl Attribute {
    fn lookup<'a>(attributes: &'a [Attribute], name: &str) -> Option<&'a AttrValue> {
        attributes
            .iter()
            .rev()
            .find(|attribute| attribute.name == name)
            .map(|attribute| &attribute.value)
    }
}

fn parse_start_element(
    chunk: &[u8],
    header_size: usize,
    pool: &[String],
    manifest: &mut AxmlManifest,
) -> Result<(), String> {
    manifest.element_count += 1;
    let name_index = u32_at(chunk, 20).ok_or("bad element name index")?;
    let element_name = pool_get(pool, name_index).unwrap_or("");
    let attribute_start = u16_at(chunk, 24).ok_or("bad attribute start")? as usize;
    let attribute_size = u16_at(chunk, 26).ok_or("bad attribute size")? as usize;
    let attribute_count = u16_at(chunk, 28).ok_or("bad attribute count")? as usize;

    let attributes_offset = header_size
        .checked_add(attribute_start)
        .ok_or("attribute offset overflow")?;
    if attribute_size < 20 {
        return Err("unsupported attribute size".to_string());
    }
    let mut attributes = Vec::with_capacity(attribute_count);
    for index in 0..attribute_count {
        let base = attributes_offset + index * attribute_size;
        let name_index = u32_at(chunk, base + 4).ok_or("bad attribute name index")?;
        let raw_value = u32_at(chunk, base + 8).unwrap_or(NO_INDEX);
        let data_type = *chunk.get(base + 15).ok_or("bad attribute type")?;
        let data_value = u32_at(chunk, base + 16).ok_or("bad attribute data")?;
        let name = pool_get(pool, name_index).unwrap_or("").to_string();
        let value = match data_type {
            TYPE_STRING => AttrValue::Str(
                pool_get(pool, data_value)
                    .or_else(|| {
                        if raw_value != NO_INDEX {
                            pool_get(pool, raw_value)
                        } else {
                            None
                        }
                    })
                    .unwrap_or("")
                    .to_string(),
            ),
            TYPE_INT_DEC | TYPE_INT_HEX => AttrValue::Int(data_value as i32 as i64),
            TYPE_INT_BOOLEAN => AttrValue::Bool(data_value != 0),
            TYPE_REFERENCE => AttrValue::Ref(data_value),
            _ => {
                if raw_value != NO_INDEX {
                    AttrValue::Str(pool_get(pool, raw_value).unwrap_or("").to_string())
                } else {
                    AttrValue::Unknown
                }
            }
        };
        attributes.push(Attribute { name, value });
    }

    match element_name {
        "manifest" => {
            if let Some(value) = Attribute::lookup(&attributes, "package") {
                manifest.package = value.as_str().map(str::to_string);
            }
            if let Some(value) = Attribute::lookup(&attributes, "versionCode") {
                manifest.version_code = value.as_i64();
            }
            if let Some(value) = Attribute::lookup(&attributes, "versionName") {
                manifest.version_name = value.as_str().map(str::to_string);
            }
        }
        "uses-sdk" => {
            if let Some(value) = Attribute::lookup(&attributes, "minSdkVersion") {
                manifest.min_sdk = value.as_i64();
            }
            if let Some(value) = Attribute::lookup(&attributes, "targetSdkVersion") {
                manifest.target_sdk = value.as_i64();
            }
        }
        "uses-permission" | "uses-permission-sdk-23" => {
            if let Some(name) = Attribute::lookup(&attributes, "name").and_then(AttrValue::as_str) {
                manifest.permissions.push(name.to_string());
            }
        }
        "application" => {
            if let Some(value) = Attribute::lookup(&attributes, "debuggable") {
                manifest.debuggable = value.as_bool().unwrap_or(false);
            }
            if let Some(value) = Attribute::lookup(&attributes, "allowBackup") {
                manifest.allow_backup = value.as_bool();
            }
        }
        "activity" | "activity-alias" | "service" | "receiver" | "provider" => {
            let Some(name) = Attribute::lookup(&attributes, "name").and_then(AttrValue::as_str)
            else {
                return Ok(());
            };
            let component = Component {
                kind: element_name.to_string(),
                name: name.to_string(),
                exported: Attribute::lookup(&attributes, "exported").and_then(AttrValue::as_bool),
                permission: Attribute::lookup(&attributes, "permission")
                    .and_then(AttrValue::as_str)
                    .map(str::to_string),
            };
            if !manifest
                .components
                .iter()
                .any(|existing| existing.name == component.name && existing.kind == component.kind)
            {
                manifest.components.push(component);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Parse the binary `AndroidManifest.xml` from an APK.
pub fn parse_manifest(data: &[u8]) -> Result<AxmlManifest, String> {
    if data.len() < 8 {
        return Err("AXML too short".to_string());
    }
    let magic = u16_at(data, 0).ok_or("bad AXML magic")?;
    if magic != RES_XML_TYPE {
        return Err(format!("not AXML (type 0x{magic:04x})"));
    }
    let header_size = u16_at(data, 2).unwrap_or(8) as usize;
    let mut position = header_size.max(8);
    let mut pool: Option<Vec<String>> = None;
    let mut manifest = AxmlManifest {
        parsed: true,
        ..AxmlManifest::default()
    };

    while position + 8 <= data.len() {
        let chunk_type = u16_at(data, position).ok_or("bad chunk type")?;
        let chunk_header_size = u16_at(data, position + 2).ok_or("bad chunk header size")? as usize;
        let chunk_size = u32_at(data, position + 4).ok_or("bad chunk size")? as usize;
        if chunk_size < 8 || position + chunk_size > data.len() {
            break;
        }
        let chunk = &data[position..position + chunk_size];
        match chunk_type {
            RES_STRING_POOL_TYPE => {
                pool = Some(parse_string_pool(chunk)?);
            }
            RES_XML_START_ELEMENT_TYPE => {
                if let Some(pool) = pool.as_deref() {
                    parse_start_element(chunk, chunk_header_size, pool, &mut manifest)?;
                }
            }
            _ => {}
        }
        position += chunk_size;
    }
    if pool.is_none() {
        return Err("AXML has no string pool".to_string());
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/AndroidManifest.bin");

    #[test]
    fn parses_real_aapt2_manifest() {
        let manifest = parse_manifest(FIXTURE).expect("fixture manifest should parse");
        assert_eq!(manifest.package.as_deref(), Some("com.avero.testsample"));
        assert_eq!(manifest.version_code, Some(7));
        assert_eq!(manifest.version_name.as_deref(), Some("1.2.3"));
        assert_eq!(manifest.min_sdk, Some(24));
        assert_eq!(manifest.target_sdk, Some(34));
        assert!(manifest.debuggable);
        assert_eq!(manifest.allow_backup, Some(false));
        assert!(manifest
            .permissions
            .iter()
            .any(|value| value == "android.permission.INTERNET"));
        assert!(manifest
            .permissions
            .iter()
            .any(|value| value == "android.permission.READ_SMS"));
        assert!(manifest.components.iter().any(|component| {
            component.kind == "activity"
                && component.name == ".MainActivity"
                && component.exported == Some(true)
        }));
        assert!(manifest.components.iter().any(|component| {
            component.kind == "service"
                && component.name == ".SyncService"
                && component.permission.as_deref() == Some("com.avero.permission.SYNC")
        }));
        assert!(manifest
            .components
            .iter()
            .any(Component::is_exported_without_permission));
    }

    #[test]
    fn rejects_non_axml() {
        assert!(parse_manifest(b"not axml").is_err());
        assert!(parse_manifest(&[]).is_err());
    }
}
