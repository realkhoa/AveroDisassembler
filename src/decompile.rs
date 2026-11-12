//! Ghidra headless decompilation adapter (`avero decompile`).
//!
//! Runs Ghidra's `analyzeHeadless` with an embedded GhidraScript that exports function
//! decompilation as JSON. The engine is installed through `avero engine install ghidra`
//! (sidecar, Apache-2.0) and is never linked into this binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::engine;

/// Embedded GhidraScript (compiled by Ghidra at runtime).
const EXPORT_SCRIPT: &str = include_str!("ghidra_scripts/AveroExport.java");
const SCRIPT_NAME: &str = "AveroExport.java";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledFunction {
    pub name: String,
    pub entry: String,
    pub size: u64,
    pub decompiled: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileResult {
    pub program: String,
    pub language: String,
    pub image_base: String,
    pub functions: Vec<DecompiledFunction>,
}

#[derive(Debug, Clone, Default)]
pub struct DecompileOptions {
    /// Function name or entry-point address (hex/decimal) to decompile; empty = all.
    pub only: Option<String>,
    pub limit: usize,
    pub timeout: Duration,
}

/// Locate Ghidra's `analyzeHeadless` launcher.
pub fn locate_ghidra() -> Option<PathBuf> {
    if let Some(manifest) = engine::load_manifests()
        .into_iter()
        .find(|manifest| manifest.id == "ghidra")
    {
        if let Some(path) = engine::manifest_binary_path(&manifest) {
            return Some(path);
        }
    }
    engine::which("analyzeHeadless")
}

fn build_headless_command(launcher: &Path, args: &[String]) -> Command {
    let is_windows_script = launcher
        .extension()
        .and_then(|value| value.to_str())
        .map(|extension| matches!(extension.to_ascii_lowercase().as_str(), "bat" | "cmd"))
        .unwrap_or(false);
    if is_windows_script {
        // .bat/.cmd launchers must run through cmd; `call` handles quoted paths safely
        // (avoids the nested-quote pitfalls of passing a pre-built command line).
        let mut command = crate::util::command("cmd");
        command.arg("/c").arg("call").arg(launcher);
        command.args(args);
        command
    } else {
        let mut command = crate::util::command(launcher);
        command.args(args);
        command
    }
}

/// Run Ghidra headless and return the decompiled functions.
pub fn decompile_file(input: &Path, options: &DecompileOptions) -> Result<DecompileResult> {
    let launcher = locate_ghidra().ok_or_else(|| {
        anyhow!(
            "Ghidra is not installed. Run `avero engine install ghidra` (after `avero engine pin ghidra`)."
        )
    })?;
    if !input.is_file() {
        return Err(anyhow!("input not found: {}", input.display()));
    }
    let limit = options.limit.clamp(1, 10_000);
    let working_dir = std::env::temp_dir().join(format!(
        "avero-ghidra-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&working_dir)
        .with_context(|| format!("cannot create {}", working_dir.display()))?;
    let script_dir = working_dir.join("scripts");
    std::fs::create_dir_all(&script_dir)?;
    std::fs::write(script_dir.join(SCRIPT_NAME), EXPORT_SCRIPT)?;
    let output_json = working_dir.join("decompile.json");
    let project_dir = working_dir.join("project");
    // analyzeHeadless requires the project parent directory to exist.
    std::fs::create_dir_all(&project_dir)
        .with_context(|| format!("cannot create {}", project_dir.display()))?;

    let mut args: Vec<String> = vec![
        project_dir.to_string_lossy().to_string(),
        "AveroProject".to_string(),
        "-import".to_string(),
        input.to_string_lossy().to_string(),
        "-scriptPath".to_string(),
        script_dir.to_string_lossy().to_string(),
        "-postScript".to_string(),
        SCRIPT_NAME.to_string(),
        output_json.to_string_lossy().to_string(),
        options.only.clone().unwrap_or_default(),
        limit.to_string(),
        "-deleteProject".to_string(),
    ];
    // Analyzing large binaries is slow; Ghidra enforces its own analysis timeout.
    args.push("-analysisTimeoutPerFile".to_string());
    args.push("600".to_string());

    let mut command = build_headless_command(&launcher, &args);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("cannot launch {}", launcher.display()))?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > options.timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!(
                "Ghidra headless timed out after {}s",
                options.timeout.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    let output = child.wait_with_output()?;
    if !status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let _ = std::fs::remove_dir_all(&working_dir);
        return Err(anyhow!(
            "Ghidra headless failed ({}):\n{}\n{}",
            status,
            tail(&stderr, 4000),
            tail(&stdout, 1500)
        ));
    }
    let raw = std::fs::read_to_string(&output_json).with_context(|| {
        format!(
            "Ghidra finished but produced no output at {}",
            output_json.display()
        )
    })?;
    let _ = std::fs::remove_dir_all(&working_dir);
    serde_json::from_str(&raw).with_context(|| "cannot parse Ghidra decompile JSON")
}

/// Last `count` characters of a text, for bounded error messages.
fn tail(text: &str, count: usize) -> String {
    let characters: Vec<char> = text.chars().collect();
    let start = characters.len().saturating_sub(count);
    characters[start..].iter().collect()
}

/// Safe file name for a decompiled function.
pub fn function_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "function".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_sanitized() {
        assert_eq!(function_file_name("main"), "main");
        assert_eq!(function_file_name("Foo::Bar<int>"), "Foo__Bar_int_");
        assert_eq!(function_file_name(""), "function");
    }

    #[test]
    fn result_json_round_trips() {
        let result = DecompileResult {
            program: "sample.exe".into(),
            language: "x86:LE:64:default".into(),
            image_base: "140000000".into(),
            functions: vec![DecompiledFunction {
                name: "entry".into(),
                entry: "0x140001000".into(),
                size: 42,
                decompiled: "int entry(void) { return 0; }".into(),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: DecompileResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.functions.len(), 1);
        assert_eq!(parsed.functions[0].name, "entry");
    }
}
