//! End-to-end CLI tests (invoke the real release/debug binary).

use std::path::PathBuf;
use std::process::Command;

use tempfile::tempdir;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_avero"))
        .args(args)
        .output()
        .expect("failed to spawn avero")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn write_elf(path: &PathBuf) {
    let mut data = vec![0u8; 128];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2;
    data[5] = 1;
    data[16..18].copy_from_slice(&2u16.to_le_bytes());
    data[18..20].copy_from_slice(&62u16.to_le_bytes());
    std::fs::write(path, data).expect("write elf fixture");
}

#[test]
fn version_prints_tool_info() {
    let output = run(&["version"]);
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("avero"));
    assert!(text.contains("native Rust"));
    assert!(text.contains("no Python"));
}

#[test]
fn probe_json_identifies_elf() {
    let directory = tempdir().expect("tempdir");
    let target = directory.path().join("sample.elf");
    write_elf(&target);
    let output = run(&["probe", target.to_str().unwrap(), "--json"]);
    assert!(output.status.success(), "{}", stdout(&output));
    let payload: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(payload["kinds"][0], "elf");
    assert_eq!(payload["architecture"], "x86_64");
    assert_eq!(payload["bits"], 64);
}

#[test]
fn scan_writes_reports() {
    let directory = tempdir().expect("tempdir");
    let target = directory.path().join("sample.elf");
    write_elf(&target);
    let out = directory.path().join("reports");
    let output = run(&[
        "scan",
        target.to_str().unwrap(),
        "--no-cache",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", stdout(&output));
    let report_path = out.join("report.json");
    assert!(report_path.is_file());
    assert!(out.join("report.md").is_file());
    assert!(out.join("report.html").is_file());
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(report_path).expect("read")).expect("json");
    assert_eq!(report["schema_id"], "avero.report/v1");
    assert_eq!(report["tool"]["name"], "avero");
    assert!(report["artifact"]["id"].as_str().unwrap().len() == 64);
}

#[test]
fn scan_json_stdout_is_machine_readable() {
    let directory = tempdir().expect("tempdir");
    let target = directory.path().join("sample.elf");
    write_elf(&target);
    let output = run(&["scan", target.to_str().unwrap(), "--json", "--no-cache"]);
    assert!(output.status.success());
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("stdout must be valid JSON");
    assert_eq!(report["schema_id"], "avero.report/v1");
    assert!(report["coverage"]["strings.generic"].is_string());
}

#[test]
fn strings_command_extracts_ascii() {
    let directory = tempdir().expect("tempdir");
    let target = directory.path().join("blob.bin");
    std::fs::write(&target, b"\x00hello avero world\x00second string here\x00").expect("write");
    let output = run(&["strings", target.to_str().unwrap(), "--min-len", "5"]);
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("hello avero world"));
    assert!(text.contains("second string here"));
}

#[test]
fn engine_list_shows_packs() {
    let output = run(&["engine", "list"]);
    assert!(output.status.success());
    let text = stdout(&output).to_lowercase();
    assert!(text.contains("ghidra"));
    assert!(text.contains("rizin"));
}

#[test]
fn scan_missing_file_fails() {
    let output = run(&["scan", "Z:/definitely/not/here.exe"]);
    assert!(!output.status.success());
}
