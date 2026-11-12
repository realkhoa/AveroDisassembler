//! Managed (.NET) metadata analyzer.
//!
//! Parses the CLI header → metadata root (BSJB) → `#~`/`#Strings` streams by hand. This is
//! intentionally dependency-free and bounds-checked: obfuscated assemblies break every
//! assumption, so failures degrade to a warning instead of a crash.

use serde_json::json;

use crate::analyzers::{AnalysisContext, Analyzer, Fragment};
use crate::evidence::{loc, make_evidence};
use crate::findings::make_finding;
use crate::ir::{Artifact, Kind, Severity};
use crate::pehdr;

const ENGINE: &str = "avero.dotnet";
const MAX_SAMPLE_TYPES: usize = 40;

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn read_index(data: &[u8], offset: usize, width: usize) -> Option<usize> {
    match width {
        2 => read_u16(data, offset).map(|value| value as usize),
        4 => read_u32(data, offset).map(|value| value as usize),
        _ => None,
    }
}

fn simple_index(rows: u32) -> usize {
    if rows < 0x1_0000 {
        2
    } else {
        4
    }
}

/// Size of a coded index: tag bits + bits needed for the largest referenced table.
fn coded_index_size(row_counts: &[u32; 64], tables: &[usize], tag_bits: u32) -> usize {
    let max_rows = tables
        .iter()
        .map(|&index| row_counts.get(index).copied().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let needed = if max_rows == 0 {
        0
    } else {
        32 - max_rows.leading_zeros()
    };
    if needed + tag_bits <= 16 {
        2
    } else {
        4
    }
}

fn heap_string(heap: &[u8], index: usize) -> String {
    if index == 0 || index >= heap.len() {
        return String::new();
    }
    let end = heap[index..]
        .iter()
        .position(|&byte| byte == 0)
        .map(|position| index + position)
        .unwrap_or(heap.len());
    String::from_utf8_lossy(&heap[index..end]).to_string()
}

struct TableInfo {
    row_counts: [u32; 64],
    header_size: usize,
    string_index_size: usize,
    heap_sizes: u8,
}

impl TableInfo {
    fn parse(data: &[u8]) -> Option<Self> {
        // Bit 0 of heap_sizes: string heap indexes are 4 bytes; bit 1 GUID; bit 2 blob.
        let heap_sizes = *data.get(6)?;
        let valid = read_u64(data, 8)?;
        let mut position = 24usize;
        let mut row_counts = [0u32; 64];
        for (index, slot) in row_counts.iter_mut().enumerate() {
            if valid & (1u64 << index) != 0 {
                *slot = read_u32(data, position)?;
                position += 4;
            }
        }
        Some(TableInfo {
            row_counts,
            header_size: position,
            string_index_size: if heap_sizes & 0x01 != 0 { 4 } else { 2 },
            heap_sizes,
        })
    }

    fn guid_index_size(&self) -> usize {
        if self.heap_sizes & 0x02 != 0 {
            4
        } else {
            2
        }
    }

    fn module_row_size(&self) -> usize {
        2 + self.string_index_size + 3 * self.guid_index_size()
    }

    fn typeref_row_size(&self) -> usize {
        coded_index_size(&self.row_counts, &[0, 26, 35, 1], 2) + 2 * self.string_index_size
    }

    fn typedef_row_size(&self) -> usize {
        4 + 2 * self.string_index_size
            + coded_index_size(&self.row_counts, &[2, 1, 27], 2)
            + simple_index(self.row_counts[4])
            + simple_index(self.row_counts[6])
    }
}

/// Parsed metadata root: version, CLI header flags and the two streams we care about.
struct Metadata<'a> {
    version: String,
    tables: Option<&'a [u8]>,
    strings: Option<&'a [u8]>,
    clr_runtime_version: String,
    cor_flags: u32,
}

fn parse_metadata<'a>(data: &'a [u8], info: &pehdr::PeInfo) -> Option<Metadata<'a>> {
    let (cli_rva, _) = info.data_directory(14)?;
    if cli_rva == 0 {
        return None;
    }
    let cli_offset = info.rva_to_offset(cli_rva)?;
    let metadata_rva = read_u32(data, cli_offset + 8)?;
    let cor_flags = read_u32(data, cli_offset + 16).unwrap_or(0);
    let major = read_u16(data, cli_offset + 4).unwrap_or(0);
    let minor = read_u16(data, cli_offset + 6).unwrap_or(0);
    let metadata_offset = info.rva_to_offset(metadata_rva)?;
    if data.get(metadata_offset..metadata_offset + 4)? != b"BSJB" {
        return None;
    }
    let version_length = read_u32(data, metadata_offset + 12)? as usize;
    if version_length == 0 || version_length > 256 {
        return None;
    }
    let version_start = metadata_offset + 16;
    let version_end = version_start.checked_add(version_length)?;
    let version = String::from_utf8_lossy(data.get(version_start..version_end)?)
        .trim_end_matches('\0')
        .to_string();

    let mut position = version_end;
    let stream_count = read_u16(data, position + 2).unwrap_or(0) as usize;
    position += 4;
    let mut tables = None;
    let mut strings = None;
    for _ in 0..stream_count.min(32) {
        let offset = read_u32(data, position)? as usize;
        let size = read_u32(data, position + 4)? as usize;
        position += 8;
        let name_start = position;
        let mut name_end = name_start;
        while name_end < data.len() && data[name_end] != 0 {
            name_end += 1;
        }
        let name = String::from_utf8_lossy(data.get(name_start..name_end)?).to_string();
        let raw_length = name_end - name_start;
        // Stream headers are padded to a 4-byte boundary (including the NUL terminator).
        position = name_start + ((raw_length + 1 + 3) / 4) * 4;
        let absolute = metadata_offset.checked_add(offset)?;
        let end = absolute.checked_add(size)?;
        let slice = data.get(absolute..end)?;
        match name.as_str() {
            "#~" | "#-" => tables = Some(slice),
            "#Strings" => strings = Some(slice),
            _ => {}
        }
    }
    Some(Metadata {
        version,
        tables,
        strings,
        clr_runtime_version: format!("{major}.{minor}"),
        cor_flags,
    })
}

pub struct DotnetAnalyzer;

impl Analyzer for DotnetAnalyzer {
    fn id(&self) -> &'static str {
        "dotnet.metadata"
    }

    fn accepts(&self, artifact: &Artifact) -> bool {
        artifact.has_kind(Kind::DotNet)
    }

    fn priority(&self) -> i32 {
        12
    }

    fn run(&self, ctx: &AnalysisContext, _artifact: &Artifact) -> Fragment {
        let mut fragment = Fragment::default();
        let Some(info) = pehdr::parse(ctx.data) else {
            fragment
                .unknowns
                .push("dotnet.metadata: could not parse PE header".to_string());
            return fragment;
        };
        let Some(meta) = parse_metadata(ctx.data, &info) else {
            fragment.unknowns.push(
                "dotnet.metadata: PE is marked .NET but CLI metadata could not be read".to_string(),
            );
            return fragment;
        };

        let mut type_count = 0u32;
        let mut method_count = 0u32;
        let mut field_count = 0u32;
        let mut assembly_ref_count = 0u32;
        let mut module_name = String::new();
        let mut type_names: Vec<String> = Vec::new();

        if let (Some(tables), Some(strings)) = (meta.tables, meta.strings) {
            if let Some(table_info) = TableInfo::parse(tables) {
                type_count = table_info.row_counts[2];
                field_count = table_info.row_counts[4];
                method_count = table_info.row_counts[6];
                assembly_ref_count = table_info.row_counts[35];
                // Module.Name lives at the very start of the table stream.
                if let Some(name_index) = read_index(
                    tables,
                    table_info.header_size + 2,
                    table_info.string_index_size,
                ) {
                    module_name = heap_string(strings, name_index);
                }
                // TypeDef rows start after Module + TypeRef rows.
                let table_start = table_info.header_size
                    + table_info.row_counts[0] as usize * table_info.module_row_size()
                    + table_info.row_counts[1] as usize * table_info.typeref_row_size();
                let row_size = table_info.typedef_row_size();
                let mut offset = table_start;
                for _ in 0..type_count.min(MAX_SAMPLE_TYPES as u32) {
                    let Some(flags) = read_u32(tables, offset) else {
                        break;
                    };
                    let Some(name_index) =
                        read_index(tables, offset + 4, table_info.string_index_size)
                    else {
                        break;
                    };
                    let Some(namespace_index) = read_index(
                        tables,
                        offset + 4 + table_info.string_index_size,
                        table_info.string_index_size,
                    ) else {
                        break;
                    };
                    let _ = flags;
                    let name = heap_string(strings, name_index);
                    let namespace = heap_string(strings, namespace_index);
                    if !name.is_empty() {
                        type_names.push(if namespace.is_empty() {
                            name
                        } else {
                            format!("{namespace}.{name}")
                        });
                    }
                    offset = offset.saturating_add(row_size);
                    if offset >= tables.len() {
                        break;
                    }
                }
                fragment
                    .facts
                    .insert("table_start".into(), json!(table_start));
            } else {
                fragment
                    .warnings
                    .push("dotnet.metadata: could not parse the #~ table stream".to_string());
            }
        } else {
            fragment
                .warnings
                .push("dotnet.metadata: missing #~ or #Strings stream".to_string());
        }

        let non_ascii = type_names
            .iter()
            .filter(|name| name.chars().any(|ch| !ch.is_ascii()))
            .count();
        let short_names = type_names
            .iter()
            .filter(|name| name.chars().count() <= 2)
            .count();
        let sampled = type_names.len().max(1);
        let short_ratio = short_names as f64 / sampled as f64;
        let non_ascii_ratio = non_ascii as f64 / sampled as f64;

        fragment
            .facts
            .insert("runtime_version".into(), json!(meta.version));
        fragment.facts.insert(
            "clr_runtime_version".into(),
            json!(meta.clr_runtime_version),
        );
        fragment
            .facts
            .insert("module_name".into(), json!(module_name));
        fragment
            .facts
            .insert("type_count".into(), json!(type_count));
        fragment
            .facts
            .insert("method_count".into(), json!(method_count));
        fragment
            .facts
            .insert("field_count".into(), json!(field_count));
        fragment
            .facts
            .insert("assembly_ref_count".into(), json!(assembly_ref_count));
        fragment
            .facts
            .insert("type_names_sample".into(), json!(type_names));
        fragment.facts.insert(
            "obfuscation".into(),
            json!({
                "sampled_types": type_names.len(),
                "short_type_names": short_names,
                "non_ascii_type_names": non_ascii,
                "short_ratio": (short_ratio * 10_000.0).round() / 10_000.0,
                "non_ascii_ratio": (non_ascii_ratio * 10_000.0).round() / 10_000.0,
            }),
        );
        fragment
            .metadata
            .insert("dotnet_runtime_version".into(), json!(meta.version));
        fragment.metadata.insert(
            "dotnet_clr_runtime_version".into(),
            json!(meta.clr_runtime_version),
        );
        fragment
            .metadata
            .insert("dotnet_module".into(), json!(module_name));
        fragment
            .metadata
            .insert("dotnet_types".into(), json!(type_count));
        fragment
            .metadata
            .insert("dotnet_methods".into(), json!(method_count));
        fragment
            .metadata
            .insert("dotnet_fields".into(), json!(field_count));
        fragment
            .metadata
            .insert("dotnet_assembly_refs".into(), json!(assembly_ref_count));
        fragment.metadata.insert(
            "dotnet_cor_flags".into(),
            json!(format!("0x{:04x}", meta.cor_flags)),
        );

        let evidence = make_evidence(
            ENGINE,
            env!("CARGO_PKG_VERSION"),
            "metadata",
            loc(vec![
                ("module", json!(module_name)),
                ("runtime", json!(meta.version)),
            ]),
            Some(format!(
                ".NET module '{module_name}', runtime '{}', {type_count} types, {method_count} methods, {field_count} fields",
                meta.version
            )),
            0.95,
            Vec::new(),
        );

        if !module_name.is_empty() {
            fragment.findings.push(make_finding(
                Severity::Info,
                "managed",
                format!(".NET module: {module_name}"),
                format!(
                    "Runtime '{}' (CLR {}), {type_count} types / {method_count} methods / {field_count} fields. \
                     Decompiling IL requires the ILSpyCmd sidecar (later phase).",
                    meta.version, meta.clr_runtime_version
                ),
                &[&evidence],
                0.95,
                None,
            ));
        }
        if short_ratio >= 0.3 || non_ascii_ratio >= 0.1 {
            let obfuscation_evidence = make_evidence(
                ENGINE,
                env!("CARGO_PKG_VERSION"),
                "heuristic",
                loc(vec![
                    (
                        "short_ratio",
                        json!((short_ratio * 1000.0).round() / 1000.0),
                    ),
                    (
                        "non_ascii_ratio",
                        json!((non_ascii_ratio * 1000.0).round() / 1000.0),
                    ),
                ]),
                Some(format!(
                    "{short_names}/{sampled} type names are <=2 chars; {non_ascii} non-ASCII"
                )),
                0.65,
                Vec::new(),
            );
            fragment.findings.push(make_finding(
                Severity::Medium,
                "obfuscation",
                ".NET obfuscation indicators",
                "High proportion of very short type names or names containing non-ASCII characters — common in obfuscated assemblies \
                 (ConfuserEx, .NET Reactor, Babel, ...). Check metadata streams and method bodies as well."
                    .to_string(),
                &[&obfuscation_evidence],
                0.65,
                None,
            ));
            fragment.evidence.push(obfuscation_evidence);
        }
        fragment.unknowns.push(
            "IL/.NET decompilation not run yet (needs the ILSpyCmd sidecar in phase P2)"
                .to_string(),
        );
        fragment.evidence.push(evidence);
        fragment
    }
}

/// Kept for future assembly-row parsing (table 32 requires all prior row sizes).
#[allow(dead_code)]
fn heap_sizes_note() -> &'static str {
    "metadata table schemas: TypeDef/Module parsed; Assembly deferred"
}
