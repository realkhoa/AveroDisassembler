//! rizin disassembly adapter (`avero disasm`).
//!
//! Uses the installed rizin sidecar (LGPL-3.0, never linked) in JSON mode:
//! `rizin -q -c "s <addr>" -c "pdj <count>" <file>`.
//! `pdj` emits JSON without needing `-j` on the rizin command line.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::engine;

const MAX_INSTRUCTIONS: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Instruction {
    pub address: u64,
    #[serde(default)]
    pub bytes_hex: String,
    pub mnemonic: String,
    #[serde(default)]
    pub operands: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Disassembly {
    pub address: String,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone)]
pub struct DisasmOptions {
    /// Address to disassemble at; `None` uses rizin's `entry0`.
    pub address: Option<u64>,
    pub count: usize,
    /// Run `aa` before disassembling (slower; helps function/name seeks).
    pub analyze: bool,
}

impl Default for DisasmOptions {
    fn default() -> Self {
        DisasmOptions {
            address: None,
            count: 32,
            analyze: false,
        }
    }
}

/// Locate the installed rizin binary.
pub fn locate_rizin() -> Option<PathBuf> {
    if let Some(manifest) = engine::load_manifests()
        .into_iter()
        .find(|manifest| manifest.id == "rizin")
    {
        if let Some(path) = engine::manifest_binary_path(&manifest) {
            return Some(path);
        }
    }
    engine::which("rizin")
}

/// Parse a rizin `pdj` JSON payload.
pub fn parse_pdj_json(raw: &str) -> Result<Vec<Instruction>> {
    let value: Value =
        serde_json::from_str(raw).with_context(|| "cannot parse rizin `pdj` JSON output")?;
    let array = value
        .as_array()
        .ok_or_else(|| anyhow!("rizin `pdj` output is not a JSON array"))?;
    let mut instructions = Vec::with_capacity(array.len());
    for entry in array {
        let Some(offset) = entry
            .get("offset")
            .and_then(Value::as_u64)
            .or_else(|| entry.get("addr").and_then(Value::as_u64))
        else {
            continue;
        };
        let disasm = entry
            .get("disasm")
            .or_else(|| entry.get("opcode"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let (mnemonic, operands) = match disasm.split_once(char::is_whitespace) {
            Some((mnemonic, operands)) => (mnemonic.to_string(), operands.trim().to_string()),
            None => (disasm.trim().to_string(), String::new()),
        };
        instructions.push(Instruction {
            address: offset,
            bytes_hex: entry
                .get("bytes")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            mnemonic,
            operands,
            size: entry.get("size").and_then(Value::as_u64).unwrap_or(0),
            kind: entry
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }
    Ok(instructions)
}

/// Disassemble part of a binary with rizin.
pub fn disassemble_file(path: &Path, options: &DisasmOptions) -> Result<Disassembly> {
    let rizin = locate_rizin().ok_or_else(|| {
        anyhow!("rizin is not installed. Run `avero engine install rizin` (or `avero engine pin rizin` first).")
    })?;
    if !path.is_file() {
        return Err(anyhow!("input not found: {}", path.display()));
    }
    let count = options.count.clamp(1, MAX_INSTRUCTIONS);
    let address = options
        .address
        .map(|value| format!("0x{value:x}"))
        .unwrap_or_else(|| "entry0".to_string());
    let mut command = Command::new(&rizin);
    command.arg("-q");
    command.arg("-c").arg("e scr.color=0");
    if options.analyze {
        command.arg("-c").arg("aa");
    }
    command.arg("-c").arg(format!("s {address}"));
    command.arg("-c").arg(format!("pdj {count}"));
    command.arg(path);
    let output = command
        .output()
        .with_context(|| format!("cannot launch rizin at {}", rizin.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "rizin exited with {}: {}",
            output.status,
            stderr.chars().take(800).collect::<String>()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let instructions = parse_pdj_json(&stdout)?;
    Ok(Disassembly {
        address,
        instructions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
      {"offset":5368715712,"size":4,"opcode":"sub rsp, 0x28","disasm":"sub rsp, 0x28","bytes":"4883ec28","type":"sub"},
      {"offset":5368715716,"size":5,"opcode":"call 0x140001f98","disasm":"call 0x140001f98","bytes":"e8cf050000","type":"call"},
      {"offset":5368715721,"size":4,"opcode":"add rsp, 0x28","disasm":"add rsp, 0x28","bytes":"4883c428","type":"add"}
    ]"#;

    #[test]
    fn parses_pdj_output() {
        let instructions = parse_pdj_json(SAMPLE).expect("parse");
        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].address, 5368715712);
        assert_eq!(instructions[0].mnemonic, "sub");
        assert_eq!(instructions[0].operands, "rsp, 0x28");
        assert_eq!(instructions[0].bytes_hex, "4883ec28");
        assert_eq!(instructions[1].kind, "call");
    }

    #[test]
    fn rejects_non_array_output() {
        assert!(parse_pdj_json("{\"error\":true}").is_err());
        assert!(parse_pdj_json("not json").is_err());
    }
}
