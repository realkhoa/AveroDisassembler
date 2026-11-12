//! Local REST/SSE API (`avero.api/v1`) implementing `docs/api/openapi.yaml`.
//!
//! Design constraints:
//! - loopback only, no authentication (local single-user tool);
//! - read-only except explicit scan/decompile/engine-install jobs;
//! - no HTTP framework beyond a tiny blocking server: the API is local and bounded.

pub mod multipart;
pub mod state;

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::anyhow;
use base64::Engine as _;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::decompile;
use crate::engine;
use crate::hashing;
use crate::ir::TOOL_VERSION;
use crate::pipeline::{analyze, ScanOptions};
use crate::probe;

use state::{
    artifact_path_of, new_job_id, read_artifact_slice, AppState, Job, JobEvent, API_VERSION,
    MAX_UPLOAD_BYTES,
};

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;
const MAX_HEX_SLICE: usize = 65536;

// ------------------------------------------------------------------------------
// request/response model (glue-independent, unit-testable)
// ------------------------------------------------------------------------------

pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    fn query_usize(&self, name: &str) -> Option<usize> {
        self.query
            .get(name)
            .and_then(|value| value.parse::<usize>().ok())
    }

    fn query_str(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }
}

pub enum ApiResult {
    Json(u16, Value),
    Bytes(u16, &'static str, Vec<u8>),
    Empty(u16),
    Stream(SseBody),
}

pub struct SseBody {
    replay: VecDeque<JobEvent>,
    receiver: std::sync::mpsc::Receiver<Option<JobEvent>>,
    buffer: Vec<u8>,
    finished: bool,
}

impl SseBody {
    fn new(replay: Vec<JobEvent>, receiver: std::sync::mpsc::Receiver<Option<JobEvent>>) -> Self {
        SseBody {
            replay: replay.into(),
            receiver,
            buffer: Vec::new(),
            finished: false,
        }
    }

    fn fill(&mut self) -> bool {
        let event = if let Some(event) = self.replay.pop_front() {
            Some(event)
        } else {
            match self.receiver.recv() {
                Ok(Some(event)) => Some(event),
                _ => None,
            }
        };
        match event {
            Some(event) => {
                let encoded = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
                self.buffer = format!("data: {encoded}\n\n").into_bytes();
                if event.is_terminal() {
                    self.finished = true;
                }
                true
            }
            None => {
                self.finished = true;
                false
            }
        }
    }
}

impl Read for SseBody {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.buffer.is_empty() {
                let count = output.len().min(self.buffer.len());
                output[..count].copy_from_slice(&self.buffer[..count]);
                self.buffer.drain(..count);
                return Ok(count);
            }
            if self.finished {
                return Ok(0);
            }
            if !self.fill() {
                return Ok(0);
            }
        }
    }
}

// ------------------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------------------

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    output.push(value);
                    index += 3;
                    continue;
                }
                output.push(bytes[index]);
                index += 1;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).to_string()
}

fn parse_target(url: &str) -> (String, BTreeMap<String, String>) {
    let (path, query) = match url.split_once('?') {
        Some((path, query)) => (path, query),
        None => (url, ""),
    };
    let mut parameters = BTreeMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        parameters.insert(percent_decode(key), percent_decode(value));
    }
    (percent_decode(path), parameters)
}

fn error_json(code: &str, message: &str) -> Value {
    json!({"error": {"code": code, "message": message, "details": {}}})
}

fn not_found(message: &str) -> ApiResult {
    ApiResult::Json(404, error_json("not_found", message))
}

fn bad_request(message: &str) -> ApiResult {
    ApiResult::Json(400, error_json("bad_request", message))
}

fn not_implemented(message: &str) -> ApiResult {
    ApiResult::Json(501, error_json("not_implemented", message))
}

fn page_limit(request: &HttpRequest) -> usize {
    request
        .query_usize("limit")
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, MAX_LIMIT)
}

fn page_offset(request: &HttpRequest) -> usize {
    request
        .query_str("cursor")
        .or_else(|| request.query_str("offset"))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
}

fn next_cursor(offset: usize, returned: usize, total: usize) -> Value {
    if offset + returned < total {
        Value::String((offset + returned).to_string())
    } else {
        Value::Null
    }
}

fn cs_files(directory: &std::path::Path, output: &mut Vec<PathBuf>, depth: usize) {
    if depth > 8 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            cs_files(&path, output, depth + 1);
        } else if path.extension().and_then(|value| value.to_str()) == Some("cs") {
            output.push(path);
        }
    }
}

fn locate_ilspycmd() -> Option<PathBuf> {
    if let Some(manifest) = engine::load_manifests()
        .into_iter()
        .find(|manifest| manifest.id == "ilspycmd")
    {
        if let Some(path) = engine::manifest_binary_path(&manifest) {
            return Some(path);
        }
    }
    engine::which("ilspycmd")
}

// ------------------------------------------------------------------------------
// handlers
// ------------------------------------------------------------------------------

fn handle_health() -> ApiResult {
    let engines: BTreeMap<String, bool> = engine::load_manifests()
        .iter()
        .map(|manifest| (manifest.id.clone(), engine::is_installed(manifest)))
        .collect();
    ApiResult::Json(
        200,
        json!({
            "status": "ok",
            "core_version": TOOL_VERSION,
            "api_version": API_VERSION,
            "engines": engines,
        }),
    )
}

fn handle_report(state: &AppState, report_id: &str) -> ApiResult {
    match state.get_report(report_id) {
        Some(stored) => match serde_json::to_value(&stored.report) {
            Ok(value) => ApiResult::Json(200, value),
            Err(error) => ApiResult::Json(500, error_json("serialize_failed", &error.to_string())),
        },
        None => not_found("report not found"),
    }
}

fn handle_findings(state: &AppState, request: &HttpRequest, report_id: &str) -> ApiResult {
    let Some(stored) = state.get_report(report_id) else {
        return not_found("report not found");
    };
    let severity = request.query_str("severity");
    let category = request.query_str("category");
    let text = request.query_str("q").map(str::to_ascii_lowercase);
    let minimum_confidence = request
        .query_str("min_confidence")
        .and_then(|value| value.parse::<f64>().ok());
    let filtered: Vec<&crate::ir::Finding> = stored
        .report
        .findings
        .iter()
        .filter(|finding| {
            severity.map_or(true, |wanted| finding.severity.as_str() == wanted)
                && category.map_or(true, |wanted| finding.category == wanted)
                && minimum_confidence.map_or(true, |minimum| finding.confidence >= minimum)
                && text.as_ref().map_or(true, |needle| {
                    finding.title.to_ascii_lowercase().contains(needle)
                        || finding.detail.to_ascii_lowercase().contains(needle)
                })
        })
        .collect();
    let total = filtered.len();
    let offset = page_offset(request).min(total);
    let limit = page_limit(request);
    let items: Vec<&crate::ir::Finding> = filtered.into_iter().skip(offset).take(limit).collect();
    let returned = items.len();
    ApiResult::Json(
        200,
        json!({
            "items": items,
            "next_cursor": next_cursor(offset, returned, total),
            "total": total,
        }),
    )
}

fn handle_evidence(state: &AppState, report_id: &str, evidence_id: &str) -> ApiResult {
    let Some(stored) = state.get_report(report_id) else {
        return not_found("report not found");
    };
    match stored
        .report
        .artifact
        .evidence
        .iter()
        .find(|evidence| evidence.id == evidence_id)
    {
        Some(evidence) => match serde_json::to_value(evidence) {
            Ok(value) => ApiResult::Json(200, value),
            Err(error) => ApiResult::Json(500, error_json("serialize_failed", &error.to_string())),
        },
        None => not_found("evidence not found"),
    }
}

fn handle_strings(state: &AppState, request: &HttpRequest, report_id: &str) -> ApiResult {
    let Some(stored) = state.get_report(report_id) else {
        return not_found("report not found");
    };
    let text = request.query_str("q").map(str::to_ascii_lowercase);
    let encoding = request.query_str("encoding");
    let filtered: Vec<&crate::ir::StringEntry> = stored
        .report
        .artifact
        .strings
        .iter()
        .filter(|entry| {
            encoding.map_or(true, |wanted| entry.encoding == wanted)
                && text.as_ref().map_or(true, |needle| {
                    entry.value.to_ascii_lowercase().contains(needle)
                })
        })
        .collect();
    let total = filtered.len();
    let offset = page_offset(request).min(total);
    let limit = page_limit(request);
    let items: Vec<&crate::ir::StringEntry> =
        filtered.into_iter().skip(offset).take(limit).collect();
    let returned = items.len();
    ApiResult::Json(
        200,
        json!({
            "items": items,
            "next_cursor": next_cursor(offset, returned, total),
            "total": total,
        }),
    )
}

fn handle_hex(state: &AppState, request: &HttpRequest, report_id: &str) -> ApiResult {
    let Some(artifact_path) = artifact_path_of(state, report_id) else {
        return not_found("report not found");
    };
    let offset = match request
        .query_str("offset")
        .and_then(|value| value.parse::<u64>().ok())
    {
        Some(offset) => offset,
        None => return bad_request("missing or invalid `offset`"),
    };
    let length = request
        .query_str("length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4096)
        .clamp(1, MAX_HEX_SLICE);
    match read_artifact_slice(&artifact_path, offset, length) {
        Ok(bytes) => {
            let actual = bytes.len();
            ApiResult::Json(
                200,
                json!({
                    "offset": offset,
                    "length": actual,
                    "bytes_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
                }),
            )
        }
        Err(_) => ApiResult::Json(
            410,
            error_json(
                "artifact_unavailable",
                "artifact bytes are no longer available",
            ),
        ),
    }
}

fn handle_apk_manifest(state: &AppState, report_id: &str) -> ApiResult {
    let Some(stored) = state.get_report(report_id) else {
        return not_found("report not found");
    };
    let Some(facts) = stored
        .report
        .facts
        .get("apk.structure")
        .and_then(Value::as_object)
    else {
        return not_found("not an APK report");
    };
    ApiResult::Json(
        200,
        json!({
            "package": facts.get("apk_package").cloned().unwrap_or(Value::Null),
            "version_code": facts.get("apk_version_code").cloned().unwrap_or(Value::Null),
            "version_name": facts.get("apk_version_name").cloned().unwrap_or(Value::Null),
            "min_sdk": facts.get("apk_min_sdk").cloned().unwrap_or(Value::Null),
            "target_sdk": facts.get("apk_target_sdk").cloned().unwrap_or(Value::Null),
            "debuggable": facts.get("apk_debuggable").cloned().unwrap_or(Value::Bool(false)),
            "allow_backup": facts.get("apk_allow_backup").cloned().unwrap_or(Value::Null),
            "permissions": facts.get("apk_permissions").cloned().unwrap_or_else(|| json!([])),
            "dangerous_permissions": facts.get("apk_dangerous_permissions").cloned().unwrap_or_else(|| json!([])),
            "components": facts.get("apk_components").cloned().unwrap_or_else(|| json!([])),
        }),
    )
}

fn handle_dotnet(state: &AppState, report_id: &str) -> ApiResult {
    let Some(stored) = state.get_report(report_id) else {
        return not_found("report not found");
    };
    match stored.report.facts.get("dotnet.metadata") {
        Some(facts) => ApiResult::Json(200, facts.clone()),
        None => not_found("not a .NET report"),
    }
}

fn handle_engines() -> ApiResult {
    let items: Vec<Value> = engine::load_manifests()
        .iter()
        .map(|manifest| {
            json!({
                "id": manifest.id,
                "name": manifest.name.clone().unwrap_or_else(|| manifest.id.clone()),
                "version": manifest.version,
                "license": manifest.license,
                "integration": manifest.integration,
                "installed": engine::is_installed(manifest),
                "binary": engine::manifest_binary_path(manifest).map(|path| path.to_string_lossy().to_string()),
                "homepage": manifest.homepage,
            })
        })
        .collect();
    ApiResult::Json(200, json!({"items": items}))
}

fn handle_job_snapshot(state: &AppState, job_id: &str) -> ApiResult {
    match state.get_job(job_id) {
        Some(job) => match serde_json::to_value(job.snapshot()) {
            Ok(value) => ApiResult::Json(200, value),
            Err(error) => ApiResult::Json(500, error_json("serialize_failed", &error.to_string())),
        },
        None => not_found("job not found"),
    }
}

fn handle_job_events(state: &AppState, job_id: &str) -> ApiResult {
    match state.get_job(job_id) {
        Some(job) => {
            let (replay, receiver) = job.subscribe();
            ApiResult::Stream(SseBody::new(replay, receiver))
        }
        None => not_found("job not found"),
    }
}

fn parse_scan_options(raw: Option<&[u8]>) -> ScanOptions {
    let mut options = ScanOptions::default();
    let Some(raw) = raw else {
        return options;
    };
    let Ok(value) = serde_json::from_slice::<Value>(raw) else {
        return options;
    };
    if let Some(minimum) = value.get("min_string_len").and_then(Value::as_u64) {
        options.min_string_len = minimum as usize;
    }
    if let Some(maximum) = value.get("max_strings").and_then(Value::as_u64) {
        options.max_strings = maximum as usize;
    }
    if let Some(only) = value.get("only").and_then(Value::as_str) {
        options.enabled = Some(
            only.split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect(),
        );
    }
    if let Some(skip) = value.get("skip").and_then(Value::as_str) {
        options.disabled = skip
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect();
    }
    options
}

fn handle_scan(state: &Arc<AppState>, request: &HttpRequest) -> ApiResult {
    let Some(content_type) = request.header("content-type") else {
        return bad_request("missing Content-Type (expected multipart/form-data)");
    };
    let parts = match multipart::parse(content_type, &request.body) {
        Ok(parts) => parts,
        Err(error) => return bad_request(&format!("invalid multipart body: {error}")),
    };
    let file = parts
        .iter()
        .find(|part| part.name.as_deref() == Some("file") || part.filename.is_some());
    let Some(file) = file else {
        return bad_request("multipart body has no `file` part");
    };
    let options_bytes = parts
        .iter()
        .find(|part| part.name.as_deref() == Some("options"))
        .map(|part| part.body.as_slice());
    let options = parse_scan_options(options_bytes);
    let filename = file
        .filename
        .clone()
        .unwrap_or_else(|| "upload.bin".to_string());
    let bytes = file.body.clone();
    let digest = hashing::digest(&bytes);
    let report_id = digest.sha256.clone();

    if state.get_report(&report_id).is_some() {
        let job = Job::new(new_job_id());
        job.publish(JobEvent::done(
            &job.id,
            Some(report_id.clone()),
            Some(json!({
                "report_id": report_id,
                "report_url": format!("/api/reports/{report_id}"),
            })),
        ));
        let job_id = job.id.clone();
        state.insert_job(job);
        return ApiResult::Json(202, json!({"job_id": job_id, "status": "done"}));
    }

    let job = Job::new(new_job_id());
    let job_id = job.id.clone();
    state.insert_job(job.clone());
    let state_clone = state.clone();
    let thread_job_id = job_id.clone();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            job.publish(JobEvent::progress(
                &thread_job_id,
                "probe",
                5.0,
                "probing artifact",
            ));
            let mut artifact = probe::probe_bytes(&bytes, Some(std::path::Path::new(&filename)));
            job.publish(JobEvent::progress(
                &thread_job_id,
                "analyze",
                20.0,
                "running analyzers",
            ));
            let report = analyze(&mut artifact, &bytes, &options);
            job.publish(JobEvent::progress(
                &thread_job_id,
                "report",
                85.0,
                "writing report",
            ));
            state_clone
                .store_report(report, &bytes)
                .map(|stored| stored.report.artifact.id.clone())
        }));
        match result {
            Ok(Ok(report_id)) => job.publish(JobEvent::done(
                &thread_job_id,
                Some(report_id.clone()),
                Some(json!({
                    "report_id": report_id,
                    "report_url": format!("/api/reports/{report_id}"),
                })),
            )),
            Ok(Err(error)) => job.publish(JobEvent::error(
                &thread_job_id,
                "store_failed",
                &error.to_string(),
            )),
            Err(_) => job.publish(JobEvent::error(
                &thread_job_id,
                "internal_error",
                "scan panicked",
            )),
        }
    });
    ApiResult::Json(202, json!({"job_id": job_id, "status": "queued"}))
}

fn handle_decompile(state: &Arc<AppState>, request: &HttpRequest, report_id: &str) -> ApiResult {
    let Some(stored) = state.get_report(report_id) else {
        return not_found("report not found");
    };
    let body: Value = serde_json::from_slice(&request.body).unwrap_or_else(|_| json!({}));
    let engine_name = body
        .get("engine")
        .and_then(Value::as_str)
        .unwrap_or("ilspycmd")
        .to_ascii_lowercase();
    let type_name = body.get("type").and_then(Value::as_str).map(str::to_string);
    let function_limit = body
        .get("limit")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(50)
        .clamp(1, 500);
    let assembly = stored.artifact_path.clone();
    if engine_name == "ghidra" {
        return start_ghidra_decompile(state, assembly, type_name, function_limit);
    }
    let Some(tool) = locate_ilspycmd() else {
        return ApiResult::Json(
            409,
            error_json(
                "engine_missing",
                "ilspycmd is not installed; run `avero engine install ilspycmd`",
            ),
        );
    };
    let job = Job::new(new_job_id());
    let job_id = job.id.clone();
    state.insert_job(job.clone());
    let state_clone = state.clone();
    let thread_job_id = job_id.clone();
    std::thread::spawn(move || {
        job.publish(JobEvent::progress(
            &thread_job_id,
            "decompile",
            10.0,
            "running ILSpyCmd",
        ));
        let out_dir = state_clone.work_dir.join("decompile").join(&thread_job_id);
        if let Err(error) = std::fs::create_dir_all(&out_dir) {
            job.publish(JobEvent::error(
                &thread_job_id,
                "io_error",
                &error.to_string(),
            ));
            return;
        }
        let mut command = engine::command_for_binary(&tool);
        command.arg(&assembly).arg("-o").arg(&out_dir);
        if let Some(type_name) = &type_name {
            command.arg("-t").arg(type_name);
        }
        match command.output() {
            Ok(output) if output.status.success() => {
                let mut files = Vec::new();
                cs_files(&out_dir, &mut files, 0);
                files.sort();
                let items: Vec<Value> = files
                    .iter()
                    .filter_map(|path| {
                        let content = std::fs::read_to_string(path).ok()?;
                        Some(json!({
                            "name": path.file_name().map(|name| name.to_string_lossy().to_string()),
                            "path": path.to_string_lossy(),
                            "content": content,
                        }))
                    })
                    .collect();
                job.publish(JobEvent::done(
                    &thread_job_id,
                    None,
                    Some(json!({
                        "engine": tool.to_string_lossy(),
                        "type": type_name,
                        "out_dir": out_dir.to_string_lossy(),
                        "files": items,
                    })),
                ));
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                job.publish(JobEvent::error(
                    &thread_job_id,
                    "decompile_failed",
                    &format!(
                        "ilspycmd exited with {}: {}",
                        output.status,
                        stderr.chars().take(1200).collect::<String>()
                    ),
                ));
            }
            Err(error) => job.publish(JobEvent::error(
                &thread_job_id,
                "engine_failed",
                &error.to_string(),
            )),
        }
    });
    ApiResult::Json(202, json!({"job_id": job_id, "status": "queued"}))
}

/// Start a native decompilation job through Ghidra headless.
fn start_ghidra_decompile(
    state: &Arc<AppState>,
    assembly: PathBuf,
    only: Option<String>,
    limit: usize,
) -> ApiResult {
    if decompile::locate_ghidra().is_none() {
        return ApiResult::Json(
            409,
            error_json(
                "engine_missing",
                "Ghidra is not installed; run `avero engine install ghidra` (requires JDK 25+)",
            ),
        );
    }
    let job = Job::new(new_job_id());
    let job_id = job.id.clone();
    state.insert_job(job.clone());
    let thread_job_id = job_id.clone();
    std::thread::spawn(move || {
        job.publish(JobEvent::progress(
            &thread_job_id,
            "decompile",
            10.0,
            "running Ghidra headless",
        ));
        let options = decompile::DecompileOptions {
            only,
            limit,
            timeout: std::time::Duration::from_secs(900),
        };
        match decompile::decompile_file(&assembly, &options) {
            Ok(result) => {
                let files: Vec<Value> = result
                    .functions
                    .iter()
                    .map(|function| {
                        json!({
                            "name": format!("{}.c", decompile::function_file_name(&function.name)),
                            "entry": function.entry,
                            "size": function.size,
                            "content": function.decompiled,
                        })
                    })
                    .collect();
                job.publish(JobEvent::done(
                    &thread_job_id,
                    None,
                    Some(json!({
                        "engine": "ghidra",
                        "program": result.program,
                        "language": result.language,
                        "image_base": result.image_base,
                        "files": files,
                    })),
                ));
            }
            Err(error) => job.publish(JobEvent::error(
                &thread_job_id,
                "decompile_failed",
                &error.to_string(),
            )),
        }
    });
    ApiResult::Json(202, json!({"job_id": job_id, "status": "queued"}))
}

fn handle_engine_install(state: &Arc<AppState>, engine_id: &str) -> ApiResult {
    let manifests = engine::load_manifests();
    let Some(manifest) = manifests.iter().find(|manifest| manifest.id == engine_id) else {
        return not_found("engine not found");
    };
    let manifest = manifest.clone();
    let job = Job::new(new_job_id());
    let job_id = job.id.clone();
    state.insert_job(job.clone());
    let thread_job_id = job_id.clone();
    std::thread::spawn(move || {
        job.publish(JobEvent::progress(
            &thread_job_id,
            "install",
            5.0,
            "installing engine",
        ));
        let options = engine::InstallOptions::default();
        match engine::install_engine(&manifest, &options) {
            Ok(path) => job.publish(JobEvent::done(
                &thread_job_id,
                None,
                Some(json!({
                    "engine": manifest.id,
                    "installed": path.to_string_lossy(),
                })),
            )),
            Err(error) => job.publish(JobEvent::error(
                &thread_job_id,
                "install_failed",
                &error.to_string(),
            )),
        }
    });
    ApiResult::Json(202, json!({"job_id": job_id, "status": "queued"}))
}

// ------------------------------------------------------------------------------
// routing
// ------------------------------------------------------------------------------

pub fn handle_request(state: &Arc<AppState>, request: &HttpRequest) -> ApiResult {
    let segments: Vec<&str> = request.path.trim_matches('/').split('/').collect();
    match request.method.as_str() {
        "OPTIONS" => ApiResult::Empty(204),
        "GET" => match segments.as_slice() {
            ["api", "health"] => handle_health(),
            ["api", "reports", report_id] => handle_report(state, report_id),
            ["api", "reports", report_id, "findings"] => handle_findings(state, request, report_id),
            ["api", "reports", report_id, "evidence", evidence_id] => {
                handle_evidence(state, report_id, evidence_id)
            }
            ["api", "reports", report_id, "sections"] => match state.get_report(report_id) {
                Some(stored) => {
                    ApiResult::Json(200, json!({"items": stored.report.artifact.sections}))
                }
                None => not_found("report not found"),
            },
            ["api", "reports", report_id, "imports"] => match state.get_report(report_id) {
                Some(stored) => {
                    ApiResult::Json(200, json!({"items": stored.report.artifact.imports}))
                }
                None => not_found("report not found"),
            },
            ["api", "reports", report_id, "exports"] => match state.get_report(report_id) {
                Some(stored) => {
                    ApiResult::Json(200, json!({"items": stored.report.artifact.exports}))
                }
                None => not_found("report not found"),
            },
            ["api", "reports", report_id, "strings"] => handle_strings(state, request, report_id),
            ["api", "reports", report_id, "hex"] => handle_hex(state, request, report_id),
            ["api", "reports", report_id, "apk-manifest"] => handle_apk_manifest(state, report_id),
            ["api", "reports", report_id, "dotnet"] => handle_dotnet(state, report_id),
            ["api", "reports", _report_id, "disassembly"] => {
                not_implemented("disassembly is not implemented yet")
            }
            ["api", "jobs", job_id] => handle_job_snapshot(state, job_id),
            ["api", "jobs", job_id, "events"] => handle_job_events(state, job_id),
            ["api", "engines"] => handle_engines(),
            _ => not_found("route not found"),
        },
        "POST" => match segments.as_slice() {
            ["api", "scans"] => handle_scan(state, request),
            ["api", "reports", report_id, "decompile"] => {
                handle_decompile(state, request, report_id)
            }
            ["api", "engines", engine_id, "install"] => handle_engine_install(state, engine_id),
            ["api", "diffs"] => not_implemented("diff is not implemented yet"),
            _ => not_found("route not found"),
        },
        _ => ApiResult::Json(405, error_json("method_not_allowed", "unsupported method")),
    }
}

// ------------------------------------------------------------------------------
// HTTP glue (tiny_http)
// ------------------------------------------------------------------------------

fn host_allowed(host: Option<&String>) -> bool {
    let Some(host) = host else {
        return true;
    };
    let hostname = if host.starts_with('[') {
        host.split(']')
            .next()
            .unwrap_or(host)
            .trim_start_matches('[')
    } else {
        host.split(':').next().unwrap_or(host)
    };
    matches!(hostname, "127.0.0.1" | "localhost" | "::1")
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes())
        .unwrap_or_else(|_| Header::from_bytes(&b"X-Avero-Error"[..], &b"header"[..]).unwrap())
}

fn decorate<R: Read>(
    response: Response<R>,
    origin: &str,
    content_type: Option<&str>,
) -> Response<R> {
    let mut response = response
        .with_header(header("Access-Control-Allow-Origin", origin))
        .with_header(header("Vary", "Origin"))
        .with_header(header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
        .with_header(header("Access-Control-Allow-Headers", "Content-Type"))
        .with_header(header("Access-Control-Max-Age", "600"));
    if let Some(content_type) = content_type {
        response = response.with_header(header("Content-Type", content_type));
    }
    response
}

fn respond_json(request: Request, status: u16, value: &Value, origin: &str) {
    let body = serde_json::to_vec(value).unwrap_or_default();
    let response = decorate(
        Response::from_data(body).with_status_code(StatusCode(status)),
        origin,
        Some("application/json; charset=utf-8"),
    );
    let _ = request.respond(response);
}

fn handle_http(mut request: Request, state: Arc<AppState>) {
    let method = match request.method() {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Options => "OPTIONS",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Head => "HEAD",
        Method::Patch => "PATCH",
        _ => "OTHER",
    }
    .to_string();
    let (path, query) = parse_target(request.url());
    let mut headers = BTreeMap::new();
    for header in request.headers() {
        headers.insert(
            header.field.as_str().to_string().to_ascii_lowercase(),
            header.value.as_str().to_string(),
        );
    }
    if !host_allowed(headers.get("host")) {
        respond_json(
            request,
            403,
            &error_json("forbidden", "loopback host required"),
            "",
        );
        return;
    }
    if request.body_length().unwrap_or(0) > MAX_UPLOAD_BYTES {
        respond_json(
            request,
            413,
            &error_json("payload_too_large", "artifact exceeds the upload limit"),
            "",
        );
        return;
    }
    let mut body = Vec::new();
    let _ = request
        .as_reader()
        .take((MAX_UPLOAD_BYTES + 1) as u64)
        .read_to_end(&mut body);
    if body.len() > MAX_UPLOAD_BYTES {
        respond_json(
            request,
            413,
            &error_json("payload_too_large", "artifact exceeds the upload limit"),
            "",
        );
        return;
    }
    let http_request = HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    };
    let result = handle_request(&state, &http_request);
    match result {
        ApiResult::Json(status, value) => {
            respond_json(request, status, &value, &state.allow_origin);
        }
        ApiResult::Bytes(status, content_type, body) => {
            let response = decorate(
                Response::from_data(body).with_status_code(StatusCode(status)),
                &state.allow_origin,
                Some(content_type),
            );
            let _ = request.respond(response);
        }
        ApiResult::Empty(status) => {
            let response = decorate(
                Response::empty(StatusCode(status)),
                &state.allow_origin,
                None,
            );
            let _ = request.respond(response);
        }
        ApiResult::Stream(body) => {
            let response = Response::new(
                StatusCode(200),
                vec![
                    header("Content-Type", "text/event-stream; charset=utf-8"),
                    header("Cache-Control", "no-cache"),
                    header("Connection", "keep-alive"),
                    header("Access-Control-Allow-Origin", &state.allow_origin),
                    header("Vary", "Origin"),
                ],
                body,
                None,
                None,
            );
            let _ = request.respond(response);
        }
    }
}

/// Run the blocking local API server. Binds to `bind:port` (loopback by default).
pub fn run(bind: &str, port: u16, allow_origin: &str) -> anyhow::Result<()> {
    if !matches!(bind, "127.0.0.1" | "localhost" | "::1") {
        return Err(anyhow!(
            "refusing to bind `{bind}`: the Avero API is loopback-only"
        ));
    }
    let address = format!("{bind}:{port}");
    let server =
        Server::http(&address).map_err(|error| anyhow!("cannot bind {address}: {error}"))?;
    let state = AppState::new(AppState::default_work_dir(), allow_origin.to_string())?;
    println!(
        "Avero API {API_VERSION} listening on http://{}",
        server.server_addr()
    );
    println!("  CORS origin: {allow_origin}");
    println!("  work dir:    {}", state.work_dir.display());
    for request in server.incoming_requests() {
        let state = state.clone();
        std::thread::spawn(move || handle_http(request, state));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const SAMPLE_APK: &[u8] = include_bytes!("../../tests/fixtures/sample.apk");

    fn test_state() -> (Arc<AppState>, PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "avero-api-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let state = AppState::new(directory.join("work"), "http://localhost:3000").unwrap();
        (state, directory)
    }

    fn get(url: &str) -> HttpRequest {
        let (path, query) = parse_target(url);
        HttpRequest {
            method: "GET".to_string(),
            path,
            query,
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    fn scan_multipart() -> (String, Vec<u8>) {
        let boundary = "AVERO-BOUNDARY";
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename=\"sample.apk\"\r\nContent-Type: application/octet-stream\r\n\r\n",
        );
        body.extend_from_slice(SAMPLE_APK);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        (format!("multipart/form-data; boundary={boundary}"), body)
    }

    fn wait_for_job(state: &AppState, job_id: &str) -> state::JobSnapshot {
        for _ in 0..500 {
            let snapshot = state.get_job(job_id).expect("job").snapshot();
            if matches!(snapshot.status.as_str(), "done" | "failed") {
                return snapshot;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("job did not finish");
    }

    #[test]
    fn health_reports_versions() {
        let (state, directory) = test_state();
        match handle_request(&state, &get("/api/health")) {
            ApiResult::Json(200, value) => {
                assert_eq!(value["status"], "ok");
                assert_eq!(value["api_version"], API_VERSION);
            }
            _ => panic!("unexpected response"),
        }
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn scan_creates_report_and_reads_it_back() {
        let (state, directory) = test_state();
        let (content_type, body) = scan_multipart();
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), content_type);
        let request = HttpRequest {
            method: "POST".to_string(),
            path: "/api/scans".to_string(),
            query: BTreeMap::new(),
            headers,
            body,
        };
        let job_id = match handle_request(&state, &request) {
            ApiResult::Json(202, value) => value["job_id"].as_str().unwrap().to_string(),
            other => panic!("unexpected response: {:?}", std::mem::discriminant(&other)),
        };
        let snapshot = wait_for_job(&state, &job_id);
        assert_eq!(snapshot.status, "done");
        let report_id = snapshot.result.unwrap()["report_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(report_id.len(), 64);

        let report = match handle_request(&state, &get(&format!("/api/reports/{report_id}"))) {
            ApiResult::Json(200, value) => value,
            _ => panic!("report missing"),
        };
        assert_eq!(report["schema_id"], "avero.report/v1");
        assert_eq!(
            report["facts"]["apk.structure"]["apk_package"],
            "com.avero.testsample"
        );

        let findings = match handle_request(
            &state,
            &get(&format!("/api/reports/{report_id}/findings?severity=high")),
        ) {
            ApiResult::Json(200, value) => value,
            _ => panic!("findings missing"),
        };
        assert!(findings["total"].as_u64().unwrap() >= 1);

        let manifest = match handle_request(
            &state,
            &get(&format!("/api/reports/{report_id}/apk-manifest")),
        ) {
            ApiResult::Json(200, value) => value,
            _ => panic!("manifest missing"),
        };
        assert_eq!(manifest["package"], "com.avero.testsample");
        assert_eq!(manifest["debuggable"], true);

        let hex = match handle_request(
            &state,
            &get(&format!("/api/reports/{report_id}/hex?offset=0&length=4")),
        ) {
            ApiResult::Json(200, value) => value,
            _ => panic!("hex missing"),
        };
        assert_eq!(hex["length"], 4);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn sse_body_replays_and_terminates() {
        let job = Job::new("job-test".to_string());
        job.publish(JobEvent::progress("job-test", "probe", 5.0, "hi"));
        let (replay, receiver) = job.subscribe();
        job.publish(JobEvent::done("job-test", None, None));
        let mut body = SseBody::new(replay, receiver);
        let mut output = String::new();
        body.read_to_string(&mut output).expect("read");
        assert!(output.contains("\"stage\":\"probe\""));
        assert!(output.contains("\"type\":\"done\""));
    }

    #[test]
    fn host_and_query_helpers() {
        let loopback = Some("127.0.0.1:8787".to_string());
        let localhost = Some("localhost:8787".to_string());
        let remote = Some("evil.example".to_string());
        assert!(host_allowed(loopback.as_ref()));
        assert!(host_allowed(localhost.as_ref()));
        assert!(!host_allowed(remote.as_ref()));
        let (path, query) = parse_target("/api/reports/abc/strings?q=hello%20world&limit=5");
        assert_eq!(path, "/api/reports/abc/strings");
        assert_eq!(query.get("q").map(String::as_str), Some("hello world"));
        assert_eq!(query.get("limit").map(String::as_str), Some("5"));
    }

    #[test]
    fn unknown_route_is_404() {
        let (state, directory) = test_state();
        match handle_request(&state, &get("/api/nope")) {
            ApiResult::Json(404, _) => {}
            _ => panic!("expected 404"),
        }
        let _ = std::fs::remove_dir_all(directory);
    }
}
