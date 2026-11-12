//! Minimal, dependency-free PE header parser used by the probe and by analyzers that
//! need RVA→file-offset mapping (`.NET` metadata, CLI header, COR flags).
//!
//! goblin is used for the heavy import/export table work; this module stays small and
//! defensive so probing never fails on a slightly malformed PE.

#[derive(Debug, Clone)]
pub struct RawSection {
    pub name: String,
    pub va: u32,
    pub vsize: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct PeInfo {
    pub header_offset: u32,
    pub machine: u16,
    pub section_count: u16,
    pub timestamp: u32,
    pub characteristics: u16,
    pub optional_magic: u16,
    pub is_64: bool,
    pub entry_rva: u32,
    pub image_base: u64,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub data_directories: Vec<(u32, u32)>,
    pub sections: Vec<RawSection>,
}

const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;

impl PeInfo {
    /// Map a relative virtual address to a file offset using the section table.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            let start = section.va as u64;
            let span = (section.vsize.max(section.raw_size)) as u64;
            if (rva as u64) >= start && (rva as u64) < start + span {
                return Some((section.raw_offset as u64 + (rva as u64 - start)) as usize);
            }
        }
        None
    }

    pub fn data_directory(&self, index: usize) -> Option<(u32, u32)> {
        self.data_directories.get(index).copied()
    }
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Parse a PE file header. Returns `None` when the data is not a well-formed PE.
pub fn parse(data: &[u8]) -> Option<PeInfo> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return None;
    }
    let header_offset = u32_at(data, 0x3c)?;
    let header = header_offset as usize;
    if header + 24 > data.len() || data.get(header..header + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = header + 4;
    let machine = u16_at(data, coff)?;
    let section_count = u16_at(data, coff + 2)?;
    let timestamp = u32_at(data, coff + 4)?;
    let optional_size = u16_at(data, coff + 16)? as usize;
    let characteristics = u16_at(data, coff + 18)?;
    let optional = coff + 20;
    let optional_magic = u16_at(data, optional)?;
    if optional_magic != PE32_MAGIC && optional_magic != PE32_PLUS_MAGIC {
        return None;
    }
    let is_64 = optional_magic == PE32_PLUS_MAGIC;
    let entry_rva = u32_at(data, optional + 16)?;
    let image_base = if is_64 {
        let bytes: [u8; 8] = data.get(optional + 24..optional + 32)?.try_into().ok()?;
        u64::from_le_bytes(bytes)
    } else {
        u32_at(data, optional + 28)? as u64
    };
    let subsystem = u16_at(data, optional + 68)?;
    let dll_characteristics = u16_at(data, optional + 70)?;
    let dir_offset = optional + if is_64 { 108 } else { 92 };
    let dir_count = u32_at(data, dir_offset).unwrap_or(0).min(16) as usize;
    let mut data_directories = Vec::with_capacity(dir_count);
    for index in 0..dir_count {
        let entry = dir_offset + 4 + index * 8;
        match (u32_at(data, entry), u32_at(data, entry + 4)) {
            (Some(rva), Some(size)) => data_directories.push((rva, size)),
            _ => break,
        }
    }

    let section_table = optional + optional_size;
    let mut sections = Vec::with_capacity(section_count as usize);
    for index in 0..section_count as usize {
        let base = section_table + index * 40;
        if base + 40 > data.len() {
            break;
        }
        let name_bytes = &data[base..base + 8];
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..end]).to_string();
        sections.push(RawSection {
            name,
            vsize: u32_at(data, base + 8)?,
            va: u32_at(data, base + 12)?,
            raw_size: u32_at(data, base + 16)?,
            raw_offset: u32_at(data, base + 20)?,
            characteristics: u32_at(data, base + 36)?,
        });
    }

    Some(PeInfo {
        header_offset,
        machine,
        section_count,
        timestamp,
        characteristics,
        optional_magic,
        is_64,
        entry_rva,
        image_base,
        subsystem,
        dll_characteristics,
        data_directories,
        sections,
    })
}

pub fn machine_name(machine: u16) -> (&'static str, Option<u32>) {
    match machine {
        0x014c => ("x86", Some(32)),
        0x8664 => ("x86_64", Some(64)),
        0x01c0 => ("arm", Some(32)),
        0x01c4 => ("armv7", Some(32)),
        0xaa64 => ("aarch64", Some(64)),
        0x0200 => ("ia64", Some(64)),
        0x5064 => ("riscv64", Some(64)),
        0x5128 => ("riscv32", Some(32)),
        other => (machine_fallback(other), None),
    }
}

fn machine_fallback(machine: u16) -> &'static str {
    match machine {
        0x0000 => "unknown",
        _ => "pe-machine",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        let mut data = vec![0u8; 0x400];
        data[..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        data[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());
        let optional = coff + 20;
        data[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        data[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        data[optional + 24..optional + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        let section_table = optional + 0xF0;
        data[section_table..section_table + 5].copy_from_slice(b".text");
        data
    }

    #[test]
    fn parses_minimal_pe() {
        let info = parse(&minimal_pe()).expect("minimal PE should parse");
        assert_eq!(info.machine, 0x8664);
        assert!(info.is_64);
        assert_eq!(info.entry_rva, 0x1000);
        assert_eq!(info.sections.len(), 1);
        assert_eq!(info.sections[0].name, ".text");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(b"not a pe").is_none());
    }
}
