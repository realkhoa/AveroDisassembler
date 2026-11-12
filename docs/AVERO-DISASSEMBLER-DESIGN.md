# AveroDisassembler — technical design

| | |
|---|---|
| **Status** | Implemented in Rust (v0.5.0); this document describes the current architecture |
| **Related** | [Research report](RE-RESEARCH-REPORT.md) · [Implementation status](IMPLEMENTATION-STATUS.md) · [Engine packs](ENGINES.md) · [Signatures](SIGNATURES.md) |

The design started as a Python blueprint (IR first, evidence-first, license-tiered
integration). It was then implemented in Rust for speed and single-binary distribution; the
concepts below match the code in `src/`.

## 1. Goals

1. **One command for triage**: `avero scan <file>` identifies what a file is, what it
   contains, what looks suspicious, and produces a machine-readable report.
2. **Evidence-first**: every finding references evidence (producer, version, locator,
   excerpt, confidence, limitations).
3. **Reproducible**: deterministic reports; analysis cache keyed by analyzer version +
   artifact hash + options.
4. **No target execution**: static by default.
5. **Do not reimplement engines**: use the best open-source engines via sidecars (license-tiered).
6. **Fast and small**: native Rust binary, no Python, no runtime dependencies.

## 2. Architecture

```
CLI (clap) ── probe ── pipeline ── analyzers ── fragment merge ── Report ── JSON/MD/HTML
                              │
                              ├─ in-process: goblin, pehdr, zipscan, axml, signatures, md5/sha
                              ├─ sidecar: ILSpyCmd (dotnet decompile), rizin/ghidra/jadx (later)
                              └─ engine packs: manifest + installer + SHA-256 pinning
```

Module layout:

```
src/ir.rs          IR models (avero.ir/v1), serde, BTreeMap for deterministic JSON
src/probe.rs       format detection, hashes, entropy (never executes the target)
src/pehdr.rs       manual PE header parser (RVA→offset, sections, data directories)
src/zipscan.rs     ZIP central directory reader + STORED/DEFLATE entry extraction
src/axml.rs        binary AndroidManifest.xml parser (string pools, typed attributes)
src/signatures.rs  native YARA-subset engine and matcher
src/hashing.rs     md5/sha1/sha256 + entropy in a single pass
src/evidence.rs    content-addressed evidence IDs
src/findings.rs    content-addressed finding IDs
src/analyzers/     pe, elf, macho, dotnet, apk, il2cpp, strings, signatures, heuristics
src/pipeline.rs    analyzer scheduling, cache, fragment merge
src/report.rs      JSON / Markdown / HTML renderers
src/engine.rs      engine manifests, installer (curl/tar/dotnet-tool), SHA-256 pinning
src/main.rs        CLI + console rendering
```

## 3. IR (`avero.ir/v1`)

Core types:

- `Artifact` — id (sha256), size, kinds, hashes, entropy, architecture/bits/endianness,
  sections, imports, exports, strings, metadata, evidence.
- `Evidence` — id, producer (engine/version), kind, locator, excerpt, confidence, limitations.
- `Finding` — id, severity, category, title, detail, evidence IDs, confidence, remediation.
- `Report` — schema id, tool info, generated_at, artifact, findings, facts, coverage,
  unknowns, warnings.

Conventions:

- `kinds` is a set: a .NET PE is `[pe, dotnet]`; an APK is `[apk, dex]`.
- Evidence and finding IDs are content-addressed (SHA-1 of canonical fields), so re-running
  the same analysis with the same engine versions produces identical JSON.
- All maps are `BTreeMap`; report JSON is sorted and diff-friendly.

## 4. Analyzer protocol

```rust
pub struct AnalysisContext<'a> {
    pub data: &'a [u8],
    pub min_string_len: usize,
    pub max_strings: usize,
    pub max_scan_bytes: usize,
}

pub trait Analyzer {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn accepts(&self, artifact: &Artifact) -> bool;
    fn priority(&self) -> i32;                 // lower runs first
    fn requires(&self) -> &'static [&'static str] { &[] }
    fn run(&self, ctx: &AnalysisContext, artifact: &Artifact) -> Fragment;
}
```

`Fragment` contains facts, findings, evidence, sections, imports, exports, strings,
metadata, unknowns and warnings. The pipeline merges fragments into the artifact and report.
Analyzers are synchronous, independent and testable; they never print or render.

Scheduling: analyzers are sorted by `(priority, id)` and topologically ordered by `requires`.
`heuristics.generic` requires `strings.generic`, so it runs after strings are merged.

## 5. Pipeline and cache

1. Read the artifact into memory (currently the whole file; mapping is a future optimization).
2. Probe → format kinds + hashes + entropy + header metadata.
3. Select analyzers that accept the artifact kinds (plus `--only`/`--skip`).
4. For each analyzer (in order): check the cache; otherwise run it.
5. Merge the fragment; record `coverage[id] = "ok" | "ok (cached)"`.
6. De-duplicate evidence by ID; sort findings by severity then ID.
7. Build the report; renderers write JSON/Markdown/HTML.

Cache key: `sha1(analyzer.id | analyzer.version | artifact.sha256 | options.fingerprint)`.
Cached payload: compressed JSON `Fragment`. Cache location: `.avero/cache/` (or `--no-cache`).

Errors from an analyzer are caught per analyzer and recorded as warnings; a failing analyzer
never aborts a scan.

## 6. Engine adapter model

| Kind | Mechanism | Examples |
|---|---|---|
| In-process | Rust crate / pure-Rust parser | goblin, flate2, signatures |
| Sidecar CLI | `std::process::Command`, JSON/text output | ILSpyCmd, Ghidra headless, rizin, jadx |
| External service | HTTP/socket (future) | MobSF, CAPE |

Rules: no shell strings; argument arrays only; validate paths; bound output size; timeouts
for long-running engines (planned wrapper). Copyleft engines are sidecar-only.

Engine installation:

- Manifests in `engines/*.toml` define version, license, integration, binaries, install dir,
  download URL + pinned SHA-256, and healthcheck.
- `engine install` supports `zip` (download via OS `curl`, verify SHA-256, extract via `tar`)
  and `dotnet-tool` (`dotnet tool install --tool-path`).
- `engine pin` downloads the archive and writes its SHA-256 into the manifest.
- Offline installs use `--from <archive>`.
- Engines and caches are git-ignored; only manifests are tracked.

## 7. CLI

```
avero scan <file> [--json] [--out DIR] [--no-md] [--no-html] [--no-cache]
                  [--only ids] [--skip ids] [--min-string-len N] [--max-strings N] [-v]
avero probe <file> [--json]
avero strings <file> [-n N] [--limit N] [--unicode] [--ascii] [--json]
avero apk <file> [--json]
avero dotnet decompile <asm> [--type T] [--out DIR] [--json]
avero engine list | doctor | install <id> | pin <id>
avero version
```

Exit codes: `0` success, `1` failure. `--json` prints only JSON on stdout so it can be piped
into other tools.

## 8. Future surfaces (P4–P5)

- **REST API**: `POST /api/scan`, `GET /api/jobs/{id}`, `GET /api/reports/{id}` with paging
  for disassembly/strings/functions; WebSocket progress events.
- **Workbench UI**: Next.js/React (report dashboard, hex view, disassembly, CFG, findings +
  evidence panel, diff view).
- **MCP server**: narrow tools (`avero_probe`, `avero_triage`, `avero_strings`,
  `avero_disasm`, `avero_decompile`, `avero_apk_manifest`, `avero_diff`, …), bounded output,
  evidence in every result.

## 9. Security model

| Threat | Control |
|---|---|
| Malformed files crashing parsers | Bounds-checked parsers; per-analyzer error isolation; fuzz targets planned |
| Zip bombs / nested containers | Max depth/size limits; bounded reads; compression-ratio heuristics |
| Command injection via paths | Argument arrays, no shell; path validation |
| Path traversal during extraction | Installer extracts to repo-local temp dirs and validates archive paths (hardening planned) |
| Accidental target execution | Static by default; dynamic mode requires explicit opt-in (not implemented yet) |
| Network leakage | Scans are offline; only `engine install/pin` access the network |

## 10. Testing

- Unit tests per module (probe, hashing, evidence, findings, pehdr, zipscan, axml,
  signatures, strings, report, engine, util).
- Integration tests: CLI end-to-end, format matrix + determinism, analyzers (ELF/Mach-O/
  signatures), APK manifest (real APK generated by `aapt2`).
- Fixtures are generated by the project; no malware or third-party binaries are committed.
- CI: `.github/workflows/release.yml` builds and tests on `windows-latest`; tag pushes create
  a GitHub Release with the executable and SHA-256.

## 11. Roadmap

| Phase | Status | Contents |
|---|---|---|
| P0 | done | Probe, IR, CLI, report pipeline, tests |
| P1 | done | PE/.NET/ELF/Mach-O/APK analyzers, strings, heuristics, native signatures |
| P2 | partial | Engine installer + ILSpyCmd decompile done; Ghidra/rizin adapters next |
| P3 | planned | IL2CPP metadata dump, Cpp2IL/jadx adapters, `resources.arsc`, signing certificates |
| P4 | planned | Workbench UI (report viewer, hex, disassembly, CFG) |
| P5 | planned | MCP server, REST API, diff view |
| P6 | planned | Code signing, cross-platform CI matrix |

## 12. Architecture decision records (history)

- **ADR-001** — Start with Python to validate IR/pipeline/report quickly; replace the core
  with Rust for speed and distribution. *Superseded by ADR-008.*
- **ADR-002** — `avero.ir/v1` JSON Schema + deterministic IDs is the single contract.
- **ADR-003** — Copyleft engines run as sidecar processes only.
- **ADR-004** — Engine packs pin versions and SHA-256; offline installs supported.
- **ADR-005** — Static by default; dynamic analysis requires explicit opt-in.
- **ADR-006** — Every finding must reference evidence; reports include coverage/unknowns.
- **ADR-007** — Use a native YARA-subset engine instead of YARA-X for v0.5 (toolchain and
  binary-size constraints); YARA-X can return as a sidecar.
- **ADR-008** — Implement the core in Rust (single binary, no Python runtime); Python
  prototype retired before publication.
