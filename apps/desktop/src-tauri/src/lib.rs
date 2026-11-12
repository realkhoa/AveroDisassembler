//! Tauri entry point for the Avero desktop workbench.
//!
//! The Avero core is **linked into this binary** (`avero` crate dependency): the loopback
//! REST/SSE API from `avero::server` runs on a background thread inside the app process, so
//! users never start or manage a separate server. Engine manifests are seeded into the
//! per-user app-data directory and engines install there.

use std::net::TcpListener;

use tauri::{Manager, State};

struct ApiInfo {
    base_url: String,
}

/// Returns the embedded core API base URL (random free loopback port).
#[tauri::command]
fn api_base_url(info: State<'_, ApiInfo>) -> String {
    info.base_url.clone()
}

/// Seed engine manifests into the writable app-data directory and make it the working
/// directory, so caches/engines never need write access to Program Files.
fn prepare_app_data(app: &tauri::AppHandle) -> std::io::Result<std::path::PathBuf> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))?;
    let engines = data_dir.join("engines");
    std::fs::create_dir_all(&engines)?;
    for (name, contents) in [
        ("ghidra.toml", include_str!("../../../../engines/ghidra.toml")),
        ("ilspycmd.toml", include_str!("../../../../engines/ilspycmd.toml")),
        ("jadx.toml", include_str!("../../../../engines/jadx.toml")),
        ("rizin.toml", include_str!("../../../../engines/rizin.toml")),
    ] {
        let target = engines.join(name);
        if !target.is_file() {
            let _ = std::fs::write(&target, contents);
        }
    }
    std::env::set_current_dir(&data_dir)?;
    Ok(data_dir)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            prepare_app_data(app.handle())?;

            // Pick a free loopback port for the embedded core.
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            drop(listener);

            let base_url = format!("http://127.0.0.1:{port}");
            let origin = "http://tauri.localhost,tauri://localhost,https://tauri.localhost";

            std::thread::Builder::new()
                .name("avero-core-api".to_string())
                .spawn(move || {
                    if let Err(error) = avero::server::run("127.0.0.1", port, origin) {
                        eprintln!("[avero-core] embedded API failed: {error}");
                    }
                })
                .expect("spawn embedded core thread");

            app.manage(ApiInfo { base_url });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![api_base_url])
        .run(tauri::generate_context!())
        .expect("error while running the Avero desktop application");
}
