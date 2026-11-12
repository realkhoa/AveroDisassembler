//! Unity IL2CPP `global-metadata.dat` parser (types/methods/images/assemblies).
//!
//! Supported versions: 27, 27.1/27.2 (header int 27), 28, 29, 31. Older 24.x versions use
//! different struct layouts and are reported as unsupported instead of being guessed.
//!
//! Layout reference: Il2CppDumper `MetadataClass.cs` (MIT) — struct sizes are derived from
//! the version attributes (`Version(Min/Max)`) documented there.

use serde::Serialize;

pub const METADATA_MAGIC: u32 = 0xFAB1_1BAF;

const IMAGE_DEFINITION_SIZE: usize = 40;
const ASSEMBLY_DEFINITION_SIZE: usize = 64;
const TYPE_DEFINITION_SIZE: usize = 88;

#[derive(Debug, Clone, Serialize, Default)]
pub struct Il2CppImage {
    pub name: String,
    pub type_start: i32,
    pub type_count: u32,
    pub entry_point_index: i32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Il2CppType {
    pub name: String,
    pub namespace: String,
    pub token: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Il2CppMetadata {
    pub version: i32,
    pub type_count: usize,
    pub method_count: usize,
    pub image_count: usize,
    pub assembly_count: usize,
    pub images: Vec<Il2CppImage>,
    pub assemblies: Vec<String>,
    pub types_sample: Vec<Il2CppType>,
    pub methods_sample: Vec<String>,
    pub errors: Vec<String>,
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn i32_at(data: &[u8], offset: usize) -> Option<i32> {
    u32_at(data, offset).map(|value| value as i32)
}

#[derive(Debug, Default, Clone, Copy)]
struct Header {
    string_offset: usize,
    string_size: usize,
    methods_offset: usize,
    methods_size: usize,
    type_definitions_offset: usize,
    type_definitions_size: usize,
    images_offset: usize,
    images_size: usize,
    assemblies_offset: usize,
    assemblies_size: usize,
}

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], position: usize) -> Self {
        Cursor { data, position }
    }

    fn u32(&mut self) -> Result<u32, String> {
        let value = u32_at(self.data, self.position)
            .ok_or_else(|| format!("metadata header truncated at 0x{:x}", self.position))?;
        self.position += 4;
        Ok(value)
    }

    fn pair(&mut self) -> Result<(usize, usize), String> {
        let offset = self.u32()? as usize;
        let size = self.u32()? as usize;
        Ok((offset, size))
    }
}

fn parse_header(data: &[u8], version: i32) -> Result<Header, String> {
    let mut cursor = Cursor::new(data, 8);
    // stringLiteral, stringLiteralData, strings
    let (_literal_offset, _literal_size) = cursor.pair()?;
    let (_literal_data_offset, _literal_data_size) = cursor.pair()?;
    let (string_offset, string_size) = cursor.pair()?;
    // events, properties, methods
    let (_events_offset, _events_size) = cursor.pair()?;
    let (_properties_offset, _properties_size) = cursor.pair()?;
    let (methods_offset, methods_size) = cursor.pair()?;
    // default values
    let (_parameter_default_offset, _parameter_default_size) = cursor.pair()?;
    let (_field_default_offset, _field_default_size) = cursor.pair()?;
    let (_default_data_offset, _default_data_size) = cursor.pair()?;
    let (_marshaled_offset, _marshaled_size) = cursor.pair()?;
    // parameters, fields
    let (_parameters_offset, _parameters_size) = cursor.pair()?;
    let (_fields_offset, _fields_size) = cursor.pair()?;
    // generic parameters/constraints/containers
    let (_generic_parameter_offset, _generic_parameter_size) = cursor.pair()?;
    let (_generic_constraint_offset, _generic_constraint_size) = cursor.pair()?;
    let (_generic_container_offset, _generic_container_size) = cursor.pair()?;
    // nested types, interfaces, vtable, interface offsets
    let (_nested_offset, _nested_size) = cursor.pair()?;
    let (_interfaces_offset, _interfaces_size) = cursor.pair()?;
    let (_vtable_offset, _vtable_size) = cursor.pair()?;
    let (_interface_offsets_offset, _interface_offsets_size) = cursor.pair()?;
    let (type_definitions_offset, type_definitions_size) = cursor.pair()?;
    // images, assemblies
    let (images_offset, images_size) = cursor.pair()?;
    let (assemblies_offset, assemblies_size) = cursor.pair()?;
    // field refs, referenced assemblies
    let (_field_refs_offset, _field_refs_size) = cursor.pair()?;
    let (_referenced_assemblies_offset, _referenced_assemblies_size) = cursor.pair()?;
    if version < 28 {
        // attributesInfo + attributeTypes exist up to 27.2
        let (_attributes_info_offset, _attributes_info_size) = cursor.pair()?;
        let (_attribute_types_offset, _attribute_types_size) = cursor.pair()?;
    }
    if version >= 29 {
        let (_attribute_data_offset, _attribute_data_size) = cursor.pair()?;
        let (_attribute_range_offset, _attribute_range_size) = cursor.pair()?;
    }
    let (_unresolved_types_offset, _unresolved_types_size) = cursor.pair()?;
    let (_unresolved_ranges_offset, _unresolved_ranges_size) = cursor.pair()?;
    let (_windows_type_names_offset, _windows_type_names_size) = cursor.pair()?;
    let (_windows_strings_offset, _windows_strings_size) = cursor.pair()?;
    let (_exported_type_defs_offset, _exported_type_defs_size) = cursor.pair()?;
    Ok(Header {
        string_offset,
        string_size,
        methods_offset,
        methods_size,
        type_definitions_offset,
        type_definitions_size,
        images_offset,
        images_size,
        assemblies_offset,
        assemblies_size,
    })
}

fn string_at(data: &[u8], header: &Header, index: u32) -> String {
    let index = index as usize;
    if index >= header.string_size || header.string_offset + index >= data.len() {
        return String::new();
    }
    let start = header.string_offset + index;
    let end = (header.string_offset + header.string_size).min(data.len());
    let slice = &data[start..end];
    let length = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or_else(|| slice.len().min(256));
    String::from_utf8_lossy(&slice[..length]).to_string()
}

fn region_valid(data: &[u8], offset: usize, size: usize) -> bool {
    offset <= data.len() && size <= data.len().saturating_sub(offset)
}

/// Parse a `global-metadata.dat` file.
pub fn parse(data: &[u8]) -> Result<Il2CppMetadata, String> {
    if data.len() < 8 {
        return Err("metadata file is too small".to_string());
    }
    let magic = u32_at(data, 0).unwrap_or(0);
    if magic != METADATA_MAGIC {
        return Err(format!("bad IL2CPP metadata magic 0x{magic:08x}"));
    }
    let version = i32_at(data, 4).unwrap_or(0);
    if !(27..=31).contains(&version) {
        return Err(format!(
            "IL2CPP metadata version {version} is not supported by the built-in parser (supported: 27, 28, 29, 31); use the Cpp2IL sidecar"
        ));
    }
    let header = parse_header(data, version)?;
    for (name, offset, size) in [
        ("strings", header.string_offset, header.string_size),
        ("methods", header.methods_offset, header.methods_size),
        (
            "type definitions",
            header.type_definitions_offset,
            header.type_definitions_size,
        ),
        ("images", header.images_offset, header.images_size),
        (
            "assemblies",
            header.assemblies_offset,
            header.assemblies_size,
        ),
    ] {
        if !region_valid(data, offset, size) {
            return Err(format!(
                "metadata {name} region 0x{offset:x}+0x{size:x} is out of bounds (file 0x{:x})",
                data.len()
            ));
        }
    }
    let mut metadata = Il2CppMetadata {
        version,
        ..Il2CppMetadata::default()
    };
    metadata.type_count = header.type_definitions_size / TYPE_DEFINITION_SIZE;
    let method_stride = if version >= 31 { 36 } else { 32 };
    metadata.method_count = header.methods_size / method_stride;

    // images
    metadata.image_count = header.images_size / IMAGE_DEFINITION_SIZE;
    for index in 0..metadata.image_count.min(2048) {
        let base = header.images_offset + index * IMAGE_DEFINITION_SIZE;
        metadata.images.push(Il2CppImage {
            name: string_at(data, &header, u32_at(data, base).unwrap_or(u32::MAX)),
            type_start: i32_at(data, base + 8).unwrap_or(0),
            type_count: u32_at(data, base + 12).unwrap_or(0),
            entry_point_index: i32_at(data, base + 24).unwrap_or(-1),
        });
    }

    // assemblies
    metadata.assembly_count = header.assemblies_size / ASSEMBLY_DEFINITION_SIZE;
    for index in 0..metadata.assembly_count.min(512) {
        let base = header.assemblies_offset + index * ASSEMBLY_DEFINITION_SIZE;
        let name_index = u32_at(data, base + 16).unwrap_or(u32::MAX);
        metadata
            .assemblies
            .push(string_at(data, &header, name_index));
    }

    // type definitions sample (name/namespace/token only)
    for index in 0..metadata.type_count.min(2000) {
        let base = header.type_definitions_offset + index * TYPE_DEFINITION_SIZE;
        let name = string_at(data, &header, u32_at(data, base).unwrap_or(u32::MAX));
        let namespace = string_at(data, &header, u32_at(data, base + 4).unwrap_or(u32::MAX));
        if name.is_empty() {
            continue;
        }
        metadata.types_sample.push(Il2CppType {
            name,
            namespace,
            token: u32_at(data, base + 84).unwrap_or(0),
        });
    }

    // method definitions sample (names only)
    for index in 0..metadata.method_count.min(1000) {
        let base = header.methods_offset + index * method_stride;
        let name = string_at(data, &header, u32_at(data, base).unwrap_or(u32::MAX));
        if !name.is_empty() {
            metadata.methods_sample.push(name);
        }
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_metadata(version: i32) -> Vec<u8> {
        // layout: header (pairs), strings, type defs, images, assemblies, methods
        let strings = b"System\0Object\0Foo\0Namespace\0MyType\0MyMethod\0Assembly-CSharp\0";
        let string_offset = 0x200usize;
        let type_offset = 0x300usize;
        let image_offset = 0x400usize;
        let assembly_offset = 0x500usize;
        let method_offset = 0x600usize;
        let mut data = vec![0u8; 0x700];
        data[0..4].copy_from_slice(&METADATA_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&version.to_le_bytes());

        let mut pairs: Vec<(u32, u32)> = Vec::new();
        // strings
        pairs.push((string_offset as u32, strings.len() as u32));
        // literal + literal data
        pairs.insert(0, (0, 0));
        pairs.insert(1, (0, 0));
        // order: literal, literalData, strings, events, properties, methods
        // (pairs currently: [literal, literalData, strings]; fill events/properties/methods)
        pairs.push((0, 0)); // events
        pairs.push((0, 0)); // properties
        pairs.push((method_offset as u32, 32)); // methods (one 32-byte entry)
                                                // default values (3 pairs) + marshaled
        for _ in 0..3 {
            pairs.push((0, 0));
        }
        pairs.push((0, 0)); // marshaled
                            // parameters, fields
        pairs.push((0, 0));
        pairs.push((0, 0));
        // generic params/constraints/containers
        for _ in 0..3 {
            pairs.push((0, 0));
        }
        // nested, interfaces, vtable, interface offsets
        for _ in 0..4 {
            pairs.push((0, 0));
        }
        // type definitions
        pairs.push((type_offset as u32, TYPE_DEFINITION_SIZE as u32));
        // images, assemblies
        pairs.push((image_offset as u32, IMAGE_DEFINITION_SIZE as u32));
        pairs.push((assembly_offset as u32, ASSEMBLY_DEFINITION_SIZE as u32));
        // field refs, referenced assemblies
        pairs.push((0, 0));
        pairs.push((0, 0));
        if version < 28 {
            pairs.push((0, 0));
            pairs.push((0, 0));
        }
        if version >= 29 {
            pairs.push((0, 0));
            pairs.push((0, 0));
        }
        for _ in 0..3 {
            pairs.push((0, 0)); // unresolved types/ranges, windows type names
        }
        if version >= 27 {
            pairs.push((0, 0)); // windows runtime strings
        }
        pairs.push((0, 0)); // exported type definitions
        for (index, (offset, size)) in pairs.iter().enumerate() {
            data[8 + index * 8..8 + index * 8 + 4].copy_from_slice(&offset.to_le_bytes());
            data[12 + index * 8..12 + index * 8 + 4].copy_from_slice(&size.to_le_bytes());
        }

        data[string_offset..string_offset + strings.len()].copy_from_slice(strings);
        let position = |needle: &[u8]| -> u32 {
            strings
                .windows(needle.len())
                .position(|window| window == needle)
                .expect("fixture string") as u32
        };
        // type: name "MyType", namespace "Namespace", token
        let type_base = type_offset;
        data[type_base..type_base + 4].copy_from_slice(&position(b"MyType").to_le_bytes());
        data[type_base + 4..type_base + 8].copy_from_slice(&position(b"Namespace").to_le_bytes());
        data[type_base + 84..type_base + 88].copy_from_slice(&0x0200_0001u32.to_le_bytes());
        // image: name "Assembly-CSharp"
        data[image_offset..image_offset + 4]
            .copy_from_slice(&position(b"Assembly-CSharp").to_le_bytes());
        data[image_offset + 12..image_offset + 16].copy_from_slice(&1u32.to_le_bytes());
        // assembly name "Assembly-CSharp"
        data[assembly_offset + 16..assembly_offset + 20]
            .copy_from_slice(&position(b"Assembly-CSharp").to_le_bytes());
        // method name "MyMethod"
        data[method_offset..method_offset + 4]
            .copy_from_slice(&position(b"MyMethod").to_le_bytes());
        data
    }

    #[test]
    fn parses_v29_metadata() {
        let data = build_metadata(29);
        let metadata = parse(&data).expect("metadata");
        assert_eq!(metadata.version, 29);
        assert_eq!(metadata.type_count, 1);
        assert_eq!(metadata.method_count, 1);
        assert_eq!(metadata.images[0].name, "Assembly-CSharp");
        assert_eq!(metadata.types_sample[0].name, "MyType");
        assert_eq!(metadata.types_sample[0].namespace, "Namespace");
        assert_eq!(metadata.types_sample[0].token, 0x0200_0001);
        assert_eq!(metadata.methods_sample[0], "MyMethod");
        assert_eq!(metadata.assemblies[0], "Assembly-CSharp");
    }

    #[test]
    fn rejects_old_versions() {
        let data = build_metadata(24);
        let error = parse(&data).expect_err("24.x unsupported");
        assert!(error.contains("not supported"), "{error}");
    }

    #[test]
    fn rejects_bad_magic() {
        let error = parse(b"not metadata").expect_err("bad magic");
        assert!(error.contains("magic"), "{error}");
    }
}
