//! Avero CLI — fast, native triage and static analysis (no Python runtime).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Cell, Color, Table};

use avero::axml;
use avero::engine;
use avero::ir::{Report, Severity, TOOL_VERSION};
use avero::pipeline::{analyze, ScanOptions};
use avero::probe;
use avero::report as report_render;
use avero::strings::{extract_ascii, extract_utf16le};
use avero::util::human_size;
use avero::zipscan;

const DEFAULT_MAX_SCAN: usize = 64 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "avero",
    version,
    about = "Avero — fast, evidence-first reverse engineering workbench",
    long_about = "Static, evidence-based triage and analysis for PE/.NET/ELF/Mach-O/APK/IL2CPP \
                  artifacts. Native Rust binary: no Python, no runtime dependencies."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Triage + static analysis, writes JSON/Markdown/HTML reports
    Scan(ScanArgs),
    /// Identify a file without running analyzers
    Probe(ProbeArgs),
    /// Extract ASCII / UTF-16LE strings
    Strings(StringsArgs),
    /// Parse an APK's binary AndroidManifest.xml (package, permissions, components)
    Apk(ApkArgs),
    /// .NET tooling backed by external engines (ILSpyCmd)
    Dotnet {
        #[command(subcommand)]
        command: DotnetCommands,
    },
    /// Show version and environment
    Version,
    /// Run the local REST/SSE API for the workbench UI
    Serve(ServeArgs),
    /// Manage engine packs (Ghidra, rizin, ILSpyCmd, jadx, ...)
    Engine {
        #[command(subcommand)]
        command: EngineCommands,
    },
}

#[derive(Args)]
struct ScanArgs {
    /// File to analyze
    path: PathBuf,
    /// Print the report JSON to stdout instead of writing files
    #[arg(long)]
    json: bool,
    /// Output directory (default: avero-out/<name>-<sha8>)
    #[arg(long)]
    out: Option<PathBuf>,
    /// Do not write the Markdown report
    #[arg(long = "no-md")]
    no_md: bool,
    /// Do not write the HTML report
    #[arg(long = "no-html")]
    no_html: bool,
    /// Ignore the analysis cache
    #[arg(long = "no-cache")]
    no_cache: bool,
    /// Number of analyzers to run concurrently (reserved; analyzers are ordered)
    #[arg(long, default_value_t = 4)]
    jobs: usize,
    /// Only run these analyzers (comma separated)
    #[arg(long)]
    only: Option<String>,
    /// Skip these analyzers (comma separated)
    #[arg(long)]
    skip: Option<String>,
    /// Minimum string length
    #[arg(long = "min-string-len", default_value_t = 6)]
    min_string_len: usize,
    /// Maximum number of strings to collect
    #[arg(long = "max-strings", default_value_t = 50_000)]
    max_strings: usize,
    /// Print per-analyzer progress to stderr
    #[arg(long, short = 'v')]
    verbose: bool,
}

#[derive(Args)]
struct ProbeArgs {
    path: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct StringsArgs {
    path: PathBuf,
    #[arg(long = "min-len", short = 'n', default_value_t = 6)]
    min_len: usize,
    #[arg(long, default_value_t = 2000)]
    limit: usize,
    /// Only UTF-16LE strings
    #[arg(long)]
    unicode: bool,
    /// Only ASCII strings
    #[arg(long)]
    ascii: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ApkArgs {
    path: PathBuf,
    /// Print the parsed manifest as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ServeArgs {
    /// Bind address (loopback only)
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,
    /// Port for the local API
    #[arg(long, default_value_t = 8787)]
    port: u16,
    /// CORS origin allowed to call the API (the UI dev server)
    #[arg(long = "cors-origin", default_value = "http://localhost:3000")]
    cors_origin: String,
}

#[derive(Subcommand)]
enum EngineCommands {
    /// List engine packs and install status
    List,
    /// Check local prerequisites and engine availability
    Doctor,
    /// Install an engine pack (`id` or `id@version`)
    Install(EngineInstallArgs),
    /// Download an engine archive, compute SHA-256 and pin it in the manifest
    Pin(EnginePinArgs),
}

#[derive(Args)]
struct EngineInstallArgs {
    /// Engine id, optionally with version (`rizin@0.9.1`)
    pack: String,
    /// Use a local archive instead of downloading
    #[arg(long)]
    from: Option<PathBuf>,
    /// Allow installing when the manifest SHA-256 is not pinned yet
    #[arg(long = "allow-unpinned")]
    allow_unpinned: bool,
    /// Reinstall even if the install directory already exists
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct EnginePinArgs {
    /// Engine id to pin (e.g. `rizin`)
    id: String,
    /// Use a local archive instead of downloading
    #[arg(long)]
    from: Option<PathBuf>,
}

#[derive(Subcommand)]
enum DotnetCommands {
    /// Decompile an assembly (or one type) with ILSpyCmd
    Decompile(DotnetDecompileArgs),
}

#[derive(Args)]
struct DotnetDecompileArgs {
    assembly: PathBuf,
    /// Fully qualified type name, e.g. `Namespace.Class`
    #[arg(long = "type", short = 't')]
    type_name: Option<String>,
    /// Output directory (default: avero-out/decompile-<name>)
    #[arg(long, short = 'o')]
    out: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Scan(args) => run_scan(args),
        Commands::Probe(args) => run_probe(args),
        Commands::Strings(args) => run_strings(args),
        Commands::Apk(args) => run_apk(args),
        Commands::Dotnet { command } => match command {
            DotnetCommands::Decompile(args) => run_dotnet_decompile(args),
        },
        Commands::Version => run_version(),
        Commands::Serve(args) => avero::server::run(&args.bind, args.port, &args.cors_origin),
        Commands::Engine { command } => match command {
            EngineCommands::List => run_engine_list(),
            EngineCommands::Doctor => run_engine_doctor(),
            EngineCommands::Install(args) => run_engine_install(args),
            EngineCommands::Pin(args) => run_engine_pin(args),
        },
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{} {error:#}", "error:".red().bold());
            std::process::ExitCode::FAILURE
        }
    }
}

fn split_csv(value: String) -> HashSet<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn default_out_dir(path: &Path, artifact_id: &str) -> PathBuf {
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_else(|| "artifact".to_string());
    let short = &artifact_id[..8.min(artifact_id.len())];
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("avero-out")
        .join(format!("{stem}-{short}"))
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical | Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Green,
        Severity::Info => Color::Grey,
    }
}

fn run_scan(args: ScanArgs) -> Result<()> {
    let data = std::fs::read(&args.path)
        .with_context(|| format!("cannot read {}", args.path.display()))?;
    let started = Instant::now();
    let mut artifact = probe::probe_bytes(&data, Some(&args.path));

    let mut options = ScanOptions {
        min_string_len: args.min_string_len,
        max_strings: args.max_strings,
        use_cache: !args.no_cache,
        verbose: args.verbose,
        jobs: args.jobs,
        ..ScanOptions::default()
    };
    if let Some(only) = args.only {
        options.enabled = Some(split_csv(only));
    }
    if let Some(skip) = args.skip {
        options.disabled = split_csv(skip);
    }

    let report = analyze(&mut artifact, &data, &options);
    let elapsed = started.elapsed();

    if args.json {
        println!("{}", report_render::to_json(&report));
        return Ok(());
    }

    let out_dir = args
        .out
        .unwrap_or_else(|| default_out_dir(&args.path, &report.artifact.id));
    let written = report_render::write_reports(&report, &out_dir, !args.no_md, !args.no_html)
        .with_context(|| format!("cannot write reports to {}", out_dir.display()))?;
    print_summary(&report, &written, elapsed);
    Ok(())
}

fn print_summary(report: &Report, written: &[PathBuf], elapsed: std::time::Duration) {
    let artifact = &report.artifact;
    let name = artifact.path.as_deref().unwrap_or(artifact.id.as_str());
    println!();
    println!("{}", "Avero triage".bold().cyan());
    println!("  {}", name.bold());
    println!(
        "  {} · {} · {}",
        human_size(artifact.size),
        probe::human_kinds(artifact),
        match (&artifact.architecture, artifact.bits) {
            (Some(arch), Some(bits)) => format!("{arch}/{bits}-bit"),
            (Some(arch), None) => arch.clone(),
            _ => "unknown".to_string(),
        }
    );
    println!(
        "  sha256: {}",
        artifact.hashes.get("sha256").cloned().unwrap_or_default()
    );
    println!("  entropy: {:.3} bits/byte", artifact.entropy);
    println!("  scanned in {:.0} ms", elapsed.as_secs_f64() * 1000.0);

    if !report.findings.is_empty() {
        let mut table = Table::new();
        table.load_style(UTF8_FULL);
        table.set_header(vec!["Severity", "Title", "Conf", "Category"]);
        for finding in &report.findings {
            table.add_row(vec![
                Cell::new(finding.severity.as_str().to_uppercase())
                    .fg(severity_color(finding.severity)),
                Cell::new(&finding.title),
                Cell::new(format!("{:.2}", finding.confidence)),
                Cell::new(&finding.category),
            ]);
        }
        println!(
            "\n{}",
            format!("Findings ({})", report.findings.len()).bold()
        );
        println!("{table}");
    } else {
        println!("\n{}", "No findings.".green());
    }

    if !report.unknowns.is_empty() || !report.warnings.is_empty() {
        println!("\n{}", "Unknowns / warnings".yellow().bold());
        for item in &report.unknowns {
            println!("  {} {item}", "!".yellow());
        }
        for item in &report.warnings {
            println!("  {} {item}", "!".yellow());
        }
    }

    if !report.coverage.is_empty() {
        let mut table = Table::new();
        table.load_style(UTF8_FULL);
        table.set_header(vec!["Analyzer", "Status"]);
        for (analyzer, status) in &report.coverage {
            table.add_row(vec![Cell::new(analyzer), Cell::new(status)]);
        }
        println!("\n{}", "Analyzers".bold());
        println!("{table}");
    }

    println!("\n{}", "Reports written:".bold());
    for path in written {
        println!("  {}", path.display().to_string().cyan());
    }
}

fn run_probe(args: ProbeArgs) -> Result<()> {
    let data = std::fs::read(&args.path)
        .with_context(|| format!("cannot read {}", args.path.display()))?;
    let artifact = probe::probe_bytes(&data, Some(&args.path));
    if args.json {
        println!("{}", serde_json::to_string_pretty(&artifact)?);
        return Ok(());
    }
    let mut table = Table::new();
    table.load_style(UTF8_FULL);
    table.set_header(vec!["Field", "Value"]);
    table.add_row(vec![
        Cell::new("Path"),
        Cell::new(artifact.path.clone().unwrap_or_default()),
    ]);
    table.add_row(vec![
        Cell::new("Size"),
        Cell::new(format!("{} ({})", artifact.size, human_size(artifact.size))),
    ]);
    table.add_row(vec![
        Cell::new("Kinds"),
        Cell::new(probe::human_kinds(&artifact)),
    ]);
    table.add_row(vec![
        Cell::new("Architecture"),
        Cell::new(
            artifact
                .architecture
                .clone()
                .unwrap_or_else(|| "unknown".into()),
        ),
    ]);
    table.add_row(vec![
        Cell::new("Bits"),
        Cell::new(
            artifact
                .bits
                .map(|bits| bits.to_string())
                .unwrap_or_else(|| "unknown".into()),
        ),
    ]);
    table.add_row(vec![
        Cell::new("Endianness"),
        Cell::new(
            artifact
                .endianness
                .clone()
                .unwrap_or_else(|| "unknown".into()),
        ),
    ]);
    table.add_row(vec![
        Cell::new("Entropy"),
        Cell::new(format!("{:.4}", artifact.entropy)),
    ]);
    table.add_row(vec![
        Cell::new("MD5"),
        Cell::new(artifact.hashes.get("md5").cloned().unwrap_or_default()),
    ]);
    table.add_row(vec![
        Cell::new("SHA-1"),
        Cell::new(artifact.hashes.get("sha1").cloned().unwrap_or_default()),
    ]);
    table.add_row(vec![
        Cell::new("SHA-256"),
        Cell::new(artifact.hashes.get("sha256").cloned().unwrap_or_default()),
    ]);
    println!("{table}");
    if !artifact.metadata.is_empty() {
        let mut meta = Table::new();
        meta.load_style(UTF8_FULL);
        meta.set_header(vec!["Metadata", "Value"]);
        for (key, value) in &artifact.metadata {
            let rendered = match value {
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            meta.add_row(vec![Cell::new(key), Cell::new(rendered)]);
        }
        println!("\n{meta}");
    }
    Ok(())
}

fn run_strings(args: StringsArgs) -> Result<()> {
    let data = std::fs::read(&args.path)
        .with_context(|| format!("cannot read {}", args.path.display()))?;
    let scan_len = data.len().min(DEFAULT_MAX_SCAN);
    let scan = &data[..scan_len];
    let mut entries = extract_ascii(scan, args.min_len, args.limit, 0);
    entries.extend(extract_utf16le(scan, args.min_len, args.limit, 0));
    if args.unicode {
        entries.retain(|entry| entry.encoding == "utf16le");
    } else if args.ascii {
        entries.retain(|entry| entry.encoding == "ascii");
    }
    entries.sort_by(|left, right| {
        (left.offset, left.encoding.clone()).cmp(&(right.offset, right.encoding.clone()))
    });
    entries.truncate(args.limit);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        for entry in &entries {
            println!(
                "0x{:08x}  {:<7} {}",
                entry.offset, entry.encoding, entry.value
            );
        }
    }
    Ok(())
}

fn run_apk(args: ApkArgs) -> Result<()> {
    let data = std::fs::read(&args.path)
        .with_context(|| format!("cannot read {}", args.path.display()))?;
    let info =
        zipscan::scan(&data).ok_or_else(|| anyhow!("not a ZIP/APK: {}", args.path.display()))?;
    let entry = zipscan::find_entry(&info, "AndroidManifest.xml")
        .ok_or_else(|| anyhow!("APK has no AndroidManifest.xml"))?;
    let bytes = zipscan::read_entry(&data, entry)
        .ok_or_else(|| anyhow!("could not read AndroidManifest.xml (compression?)"))?;
    let manifest =
        axml::parse_manifest(&bytes).map_err(|error| anyhow!("AXML parse failed: {error}"))?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
        return Ok(());
    }
    let mut table = Table::new();
    table.load_style(UTF8_FULL);
    table.set_header(vec!["Field", "Value"]);
    table.add_row(vec![
        Cell::new("Package"),
        Cell::new(manifest.package.clone().unwrap_or_default()),
    ]);
    table.add_row(vec![
        Cell::new("Version"),
        Cell::new(format!(
            "{} ({})",
            manifest.version_name.clone().unwrap_or_else(|| "?".into()),
            manifest
                .version_code
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into())
        )),
    ]);
    table.add_row(vec![
        Cell::new("SDK"),
        Cell::new(format!(
            "min {} / target {}",
            manifest
                .min_sdk
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into()),
            manifest
                .target_sdk
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into())
        )),
    ]);
    table.add_row(vec![
        Cell::new("Debuggable"),
        Cell::new(manifest.debuggable),
    ]);
    table.add_row(vec![
        Cell::new("Allow backup"),
        Cell::new(
            manifest
                .allow_backup
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into()),
        ),
    ]);
    table.add_row(vec![
        Cell::new("Permissions"),
        Cell::new(manifest.permissions.len()),
    ]);
    table.add_row(vec![
        Cell::new("Components"),
        Cell::new(manifest.components.len()),
    ]);
    println!("{table}");

    if !manifest.permissions.is_empty() {
        println!("\n{}", "Permissions".bold());
        for permission in &manifest.permissions {
            let dangerous = permission.starts_with("android.permission.")
                && matches!(
                    permission.as_str(),
                    "android.permission.CAMERA"
                        | "android.permission.READ_SMS"
                        | "android.permission.READ_CONTACTS"
                        | "android.permission.RECORD_AUDIO"
                        | "android.permission.ACCESS_FINE_LOCATION"
                        | "android.permission.READ_PHONE_STATE"
                );
            if dangerous {
                println!("  {} {}", "!".yellow(), permission);
            } else {
                println!("  - {permission}");
            }
        }
    }
    if !manifest.components.is_empty() {
        let mut components = Table::new();
        components.load_style(UTF8_FULL);
        components.set_header(vec!["Kind", "Name", "Exported", "Permission"]);
        for component in &manifest.components {
            components.add_row(vec![
                Cell::new(&component.kind),
                Cell::new(&component.name),
                Cell::new(
                    component
                        .exported
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "?".into()),
                ),
                Cell::new(component.permission.clone().unwrap_or_default()),
            ]);
        }
        println!("\n{}", "Components".bold());
        println!("{components}");
    }
    Ok(())
}

fn run_version() -> Result<()> {
    println!("{} {}", "avero".bold().cyan(), TOOL_VERSION);
    println!("  IR schema   avero.ir/v1");
    println!("  runtime     native Rust (no Python)");
    println!(
        "  platform    {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("  repo root   {}", engine::repo_root().display());
    println!("  engines     {}", engine::engines_dir().display());
    Ok(())
}

fn run_engine_list() -> Result<()> {
    let manifests = engine::load_manifests();
    if manifests.is_empty() {
        println!("{}", "No manifests found in engines/".yellow());
        return Ok(());
    }
    let mut table = Table::new();
    table.load_style(UTF8_FULL);
    table.set_header(vec![
        "ID",
        "Version",
        "License",
        "Integration",
        "Installed",
        "Homepage",
    ]);
    for manifest in &manifests {
        table.add_row(vec![
            Cell::new(&manifest.id),
            Cell::new(&manifest.version),
            Cell::new(manifest.license.clone().unwrap_or_else(|| "?".into())),
            Cell::new(manifest.integration.clone().unwrap_or_else(|| "?".into())),
            Cell::new(if engine::is_installed(manifest) {
                "yes"
            } else {
                "no"
            }),
            Cell::new(manifest.homepage.clone().unwrap_or_default()),
        ]);
    }
    println!("{table}");
    println!(
        "{}",
        "Install: avero engine install <id>   ·   pin SHA-256: avero engine pin <id>".dimmed()
    );
    Ok(())
}

fn run_engine_install(args: EngineInstallArgs) -> Result<()> {
    let mut parts = args.pack.splitn(2, '@');
    let id = parts.next().unwrap_or_default().to_string();
    let requested_version = parts.next().map(str::to_string);
    let manifests = engine::load_manifests();
    let manifest = manifests
        .iter()
        .find(|manifest| manifest.id == id)
        .ok_or_else(|| anyhow!("unknown engine `{id}`"))?;
    if let Some(version) = &requested_version {
        if version != &manifest.version {
            return Err(anyhow!(
                "manifest {} is version {}, but {} was requested",
                id,
                manifest.version,
                version
            ));
        }
    }
    let options = engine::InstallOptions {
        from: args.from,
        allow_unpinned: args.allow_unpinned,
        force: args.force,
    };
    let installed = engine::install_engine(manifest, &options)?;
    println!(
        "{} {} {} installed at {}",
        "ok".green().bold(),
        manifest.id,
        manifest.version,
        installed.display()
    );
    if let Some(binary) = engine::manifest_binary_path(manifest) {
        println!("  binary: {}", binary.display());
    }
    Ok(())
}

fn run_engine_pin(args: EnginePinArgs) -> Result<()> {
    let options = engine::InstallOptions {
        from: args.from,
        allow_unpinned: true,
        force: false,
    };
    let (hash, manifest) = engine::pin_engine(&args.id, &options)?;
    println!(
        "{} pinned {} sha256={} -> {}",
        "ok".green().bold(),
        args.id,
        hash,
        manifest.display()
    );
    Ok(())
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

fn collect_cs_files(directory: &Path, output: &mut Vec<PathBuf>, depth: usize) {
    if depth > 8 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_cs_files(&path, output, depth + 1);
        } else if path.extension().and_then(|value| value.to_str()) == Some("cs") {
            output.push(path);
        }
    }
}

fn run_dotnet_decompile(args: DotnetDecompileArgs) -> Result<()> {
    if !args.assembly.is_file() {
        return Err(anyhow!("assembly not found: {}", args.assembly.display()));
    }
    let tool = locate_ilspycmd().ok_or_else(|| {
        anyhow!("ilspycmd is not installed — run `avero engine install ilspycmd` first")
    })?;
    let stem = args
        .assembly
        .file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "assembly".to_string());
    let out_dir = args.out.unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("avero-out")
            .join(format!("decompile-{stem}"))
    });
    std::fs::create_dir_all(&out_dir)?;

    let mut command = engine::command_for_binary(&tool);
    command.arg(&args.assembly).arg("-o").arg(&out_dir);
    if let Some(type_name) = &args.type_name {
        command.arg("-t").arg(type_name);
    }
    let output = command
        .output()
        .with_context(|| format!("cannot run {}", tool.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "ilspycmd failed ({}): {}",
            output.status,
            stderr.chars().take(1200).collect::<String>()
        ));
    }
    let mut files = Vec::new();
    collect_cs_files(&out_dir, &mut files, 0);
    files.sort();
    if args.json {
        let payload = serde_json::json!({
            "assembly": args.assembly.to_string_lossy(),
            "type": args.type_name,
            "out_dir": out_dir.to_string_lossy(),
            "engine": tool.to_string_lossy(),
            "files": files.iter().map(|path| path.to_string_lossy()).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!(
            "{} decompiled {} -> {} ({} file(s))",
            "ok".green().bold(),
            args.assembly.display(),
            out_dir.display(),
            files.len()
        );
        for file in files {
            println!("  {}", file.display());
        }
        if let Some(type_name) = &args.type_name {
            println!("  type: {type_name}");
        }
    }
    Ok(())
}

fn run_engine_doctor() -> Result<()> {
    let mut checks: Vec<(&str, String, bool)> = Vec::new();
    checks.push(("rust binary", TOOL_VERSION.to_string(), true));
    for (tool, note) in [
        ("java", "Ghidra / jadx / apktool"),
        ("dotnet", "Cpp2IL / ILSpyCmd"),
        ("node", "optional"),
        ("git", "optional"),
    ] {
        let found = engine::which(tool);
        let ok = found.is_some();
        checks.push((
            tool,
            found
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| format!("not found ({note})")),
            ok,
        ));
    }
    let mut table = Table::new();
    table.load_style(UTF8_FULL);
    table.set_header(vec!["Check", "Result", "Status"]);
    for (name, value, ok) in &checks {
        table.add_row(vec![
            Cell::new(name),
            Cell::new(value),
            Cell::new(if *ok { "ok" } else { "missing" }).fg(if *ok {
                Color::Green
            } else {
                Color::Yellow
            }),
        ]);
    }
    println!("{table}");

    let manifests = engine::load_manifests();
    if !manifests.is_empty() {
        let mut table = Table::new();
        table.load_style(UTF8_FULL);
        table.set_header(vec!["Engine", "Version", "Installed", "Integration"]);
        for manifest in &manifests {
            table.add_row(vec![
                Cell::new(&manifest.id),
                Cell::new(&manifest.version),
                Cell::new(if engine::is_installed(manifest) {
                    "yes"
                } else {
                    "no"
                }),
                Cell::new(manifest.integration.clone().unwrap_or_default()),
            ]);
        }
        println!("\n{}", "Engine packs".bold());
        println!("{table}");
    }
    Ok(())
}
