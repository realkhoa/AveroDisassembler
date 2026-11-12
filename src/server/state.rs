//! Shared server state: reports, jobs, event streams and the local work directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

use crate::ir::Report;

pub const API_VERSION: &str = "avero.api/v1";
pub const MAX_UPLOAD_BYTES: usize = 512 * 1024 * 1024;
const EVENT_HISTORY_LIMIT: usize = 256;

static JOB_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn new_job_id() -> String {
    let counter = JOB_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "job-{}-{counter}",
        crate::util::now_iso8601().replace([':', '-'], "")
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct JobEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub job_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

impl JobEvent {
    pub fn progress(job_id: &str, stage: &str, percent: f64, message: &str) -> Self {
        JobEvent {
            kind: "progress".to_string(),
            job_id: job_id.to_string(),
            stage: Some(stage.to_string()),
            percent: Some(percent),
            message: Some(message.to_string()),
            report_id: None,
            error: None,
            result: None,
        }
    }

    pub fn done(job_id: &str, report_id: Option<String>, result: Option<Value>) -> Self {
        JobEvent {
            kind: "done".to_string(),
            job_id: job_id.to_string(),
            stage: Some("done".to_string()),
            percent: Some(100.0),
            message: None,
            report_id,
            error: None,
            result,
        }
    }

    pub fn error(job_id: &str, code: &str, message: &str) -> Self {
        JobEvent {
            kind: "error".to_string(),
            job_id: job_id.to_string(),
            stage: Some("error".to_string()),
            percent: None,
            message: None,
            report_id: None,
            error: Some(serde_json::json!({"code": code, "message": message})),
            result: None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        self.kind == "done" || self.kind == "error"
    }
}

struct JobData {
    status: String,
    stage: Option<String>,
    percent: f64,
    error: Option<Value>,
    result: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobSnapshot {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    pub percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

pub struct Job {
    pub id: String,
    pub created: Instant,
    data: Mutex<JobData>,
    events: Mutex<Vec<JobEvent>>,
    subscribers: Mutex<Vec<mpsc::Sender<Option<JobEvent>>>>,
}

impl Job {
    pub fn new(id: String) -> Arc<Self> {
        Arc::new(Job {
            id,
            created: Instant::now(),
            data: Mutex::new(JobData {
                status: "queued".to_string(),
                stage: Some("queued".to_string()),
                percent: 0.0,
                error: None,
                result: None,
            }),
            events: Mutex::new(Vec::new()),
            subscribers: Mutex::new(Vec::new()),
        })
    }

    pub fn publish(&self, event: JobEvent) {
        {
            let mut data = self
                .data
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            match event.kind.as_str() {
                "progress" => {
                    data.status = "running".to_string();
                    data.stage = event.stage.clone();
                    data.percent = event.percent.unwrap_or(data.percent);
                }
                "done" => {
                    data.status = "done".to_string();
                    data.stage = event.stage.clone();
                    data.percent = 100.0;
                    data.result = event.result.clone();
                }
                "error" => {
                    data.status = "failed".to_string();
                    data.stage = event.stage.clone();
                    data.error = event.error.clone();
                }
                _ => {}
            }
        }
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        events.push(event.clone());
        if events.len() > EVENT_HISTORY_LIMIT {
            let excess = events.len() - EVENT_HISTORY_LIMIT;
            events.drain(0..excess);
        }
        drop(events);

        let terminal = event.is_terminal();
        let mut subscribers = self
            .subscribers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        subscribers.retain(|sender| sender.send(Some(event.clone())).is_ok());
        if terminal {
            subscribers.clear();
        }
    }

    pub fn snapshot(&self) -> JobSnapshot {
        let data = self
            .data
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        JobSnapshot {
            id: self.id.clone(),
            status: data.status.clone(),
            stage: data.stage.clone(),
            percent: data.percent,
            error: data.error.clone(),
            result: data.result.clone(),
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.snapshot().status.as_str(),
            "done" | "failed" | "cancelled"
        )
    }

    /// Replay buffered events and subscribe to future ones.
    pub fn subscribe(&self) -> (Vec<JobEvent>, mpsc::Receiver<Option<JobEvent>>) {
        let (sender, receiver) = mpsc::channel();
        let replay = {
            let events = self
                .events
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            events.clone()
        };
        if self.is_terminal() {
            drop(sender);
            return (replay, receiver);
        }
        let mut subscribers = self
            .subscribers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        subscribers.push(sender);
        (replay, receiver)
    }
}

pub struct StoredReport {
    pub report: Report,
    pub artifact_path: PathBuf,
    pub report_path: PathBuf,
}

pub struct AppState {
    pub started: Instant,
    pub reports: Mutex<BTreeMap<String, Arc<StoredReport>>>,
    pub jobs: Mutex<BTreeMap<String, Arc<Job>>>,
    pub allow_origin: String,
    pub work_dir: PathBuf,
}

impl AppState {
    pub fn new(work_dir: impl Into<PathBuf>, allow_origin: impl Into<String>) -> Result<Arc<Self>> {
        let work_dir = work_dir.into();
        for subdirectory in ["uploads", "reports", "decompile"] {
            std::fs::create_dir_all(work_dir.join(subdirectory))
                .with_context(|| format!("cannot create {}", work_dir.display()))?;
        }
        Ok(Arc::new(AppState {
            started: Instant::now(),
            reports: Mutex::new(BTreeMap::new()),
            jobs: Mutex::new(BTreeMap::new()),
            allow_origin: allow_origin.into(),
            work_dir,
        }))
    }

    pub fn default_work_dir() -> PathBuf {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".avero")
            .join("serve")
    }

    pub fn insert_job(&self, job: Arc<Job>) {
        self.jobs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(job.id.clone(), job);
    }

    pub fn get_job(&self, job_id: &str) -> Option<Arc<Job>> {
        self.jobs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(job_id)
            .cloned()
    }

    pub fn get_report(&self, report_id: &str) -> Option<Arc<StoredReport>> {
        self.reports
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(report_id)
            .cloned()
    }

    /// Persist the report + artifact bytes and register them in memory.
    pub fn store_report(&self, report: Report, artifact_bytes: &[u8]) -> Result<Arc<StoredReport>> {
        let report_id = report.artifact.id.clone();
        let uploads = self.work_dir.join("uploads");
        let reports = self.work_dir.join("reports");
        std::fs::create_dir_all(&uploads)?;
        std::fs::create_dir_all(&reports)?;
        let artifact_path = uploads.join(&report_id);
        if !artifact_path.is_file() {
            std::fs::write(&artifact_path, artifact_bytes)?;
        }
        let report_path = reports.join(format!("{report_id}.json"));
        std::fs::write(&report_path, crate::report::to_json(&report))?;
        let stored = Arc::new(StoredReport {
            report,
            artifact_path,
            report_path,
        });
        self.reports
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(report_id, stored.clone());
        Ok(stored)
    }

    /// Resolve the Access-Control-Allow-Origin value for a request.
    ///
    /// Local-only server: echo a configured origin or one of the built-in desktop
    /// (Tauri) / localhost dev origins; otherwise fall back to the first configured one.
    pub fn cors_origin(&self, request_origin: Option<&str>) -> String {
        const BUILTIN: &[&str] = &[
            "tauri://localhost",
            "http://tauri.localhost",
            "https://tauri.localhost",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ];
        if let Some(origin) = request_origin {
            let configured = self
                .allow_origin
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if BUILTIN.contains(&origin) || configured.into_iter().any(|allowed| allowed == origin)
            {
                return origin.to_string();
            }
        }
        self.allow_origin
            .split(',')
            .map(str::trim)
            .find(|value| !value.is_empty())
            .unwrap_or("http://localhost:3000")
            .to_string()
    }
    pub fn report_count(&self) -> usize {
        self.reports
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .len()
    }
}

pub fn artifact_path_of(state: &AppState, report_id: &str) -> Option<PathBuf> {
    state
        .get_report(report_id)
        .map(|stored| stored.artifact_path.clone())
}

pub fn read_artifact_slice(path: &Path, offset: u64, length: usize) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; length];
    let mut read = 0usize;
    while read < length {
        let count = file.read(&mut buffer[read..])?;
        if count == 0 {
            break;
        }
        read += count;
    }
    buffer.truncate(read);
    Ok(buffer)
}
