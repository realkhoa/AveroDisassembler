# Implementation status — v0.7.0 (native Rust + local API + Ghidra decompile)

| | |
|---|---|
| **Date** | 2026-11-12 |
| **Version** | 0.7.0 (Rust) |
| **Toolchain** | rustc 1.94.1 MSVC, VS 18 Community, Windows 11 26200 |
| **Binary** | `target/release/avero.exe` — **3.79 MB**, no runtime dependency |
| **Tests** | **63 passing** (44 unit + 7 CLI + 4 format + 4 analyzer + 4 APK manifest) |
| **UI** | **Not built in this repository** — specified for separate UI agents in [UI-SPEC.md](UI-SPEC.md); API contract in [docs/api/](api/README.md) and **implemented** via `avero serve` |
| **Related docs** | [Design](AVERO-DISASSEMBLER-DESIGN.md) · [Research](RE-RESEARCH-REPORT.md) · [Signatures](SIGNATURES.md) · [Engines](ENGINES.md) |

---

## 0. Why Rust instead of Python

The requirement was maximum speed with minimal Python. The Python prototype proved the
pipeline/IR/report design, but:

| Python problem | Rust solution |
|---|---|
| Startup ~450 ms, notepad scan ~2 s | Startup ~11 ms, scan ~111 ms cold / ~20 ms warm |
| Python + venv (~100 MB) required | Single 3.36 MB executable |
| Byte parsing/regex/entropy in Python | Same work in Rust, one pass, no GIL |
| Complicated packaging | Copy the executable |
| YARA/capa needed Python bindings | Native signature engine; YARA-X reserved for a sidecar |

The Python prototype was retired before publishing this repository; it is not part of the
build and no longer shipped.

---

## 1. Benchmarks (same machine, notepad.exe 352 KB)

| Task | Python prototype | Rust 0.2 | **Rust 0.5** | Speed-up |
|---|---|---|---|---|
| Cold scan | 1,980 ms | 100 ms | **~111 ms** | ~18× |
| Warm scan | 1,070 ms | 18 ms | **~20 ms** | ~53× |
| APK scan (1.2 KB, with AXML) | — | — | **~38 ms** | — |
| CLI startup | ~450 ms | 13 ms | **~11 ms** | ~40× |
| Distribution size | venv ~100 MB | 2.74 MB | **3.79 MB** | — |
| Tests | 40 pytest | 38 | **63** | — |

Measurements include ~10–13 ms of PowerShell process overhead; scan figures are averages
of five runs.

---

## 2. What works

### CLI

```powershell
avero scan <file> [--json] [--out DIR] [--no-md] [--no-html] [--no-cache] [--only ids] [--skip ids] [--min-string-len N] [--max-strings N] [-v]
avero probe <file> [--json]
avero strings <file> [-n N] [--limit N] [--unicode] [--ascii] [--json]
avero apk <file> [--json]                 # binary AndroidManifest.xml
avero dotnet decompile <asm> [--type T] [--out DIR] [--json]   # ILSpyCmd sidecar
avero engine list | doctor
avero engine install <id>[@version] [--from archive] [--allow-unpinned] [--force]
avero engine pin <id>
avero version
```

### Probe (15 format families)

PE/PE32+, .NET (COR flags → AnyCPU/x86/x64), ELF, Mach-O thin+fat, Java class,
APK/DEX/ZIP/JAR, Unity IL2CPP metadata, UnityFS, Godot PCK, firmware (squashfs/gzip/xz/
bzip2/uImage/Android boot/UBI/ChromeOS/UEFI), WASM, Python `.pyc`, scripts.

### Analyzers (9)

| Analyzer | Output |
|---|---|
| `pe.structure` | Sections+entropy+flags, imports/exports (goblin), Rich header, overlay, TLS/Authenticode, ASLR/DEP/CFG; findings for packer sections, high entropy, W+X, anti-debug/injection/network/crypto imports, timestamps |
| `elf.structure` | Sections+entropy, symbols/libraries/exports, interpreter, PIE/NX/RELRO/canary/fortify, W+X segments, executable stack, RPATH/RUNPATH, debug info, static/stripped |
| `macho.structure` | Segments/sections+entropy, dylibs, RPATH, code signature, FairPlay encryption, MH_PIE, W+X; universal binaries |
| `dotnet.metadata` | CLI header → BSJB → `#~`/`#Strings` in pure Rust: runtime, CLR, module, type/method/field counts, TypeDef names, obfuscation ratio |
| `apk.structure` | ZIP structure + **AXML manifest**: package, versionCode/Name, min/target SDK, permissions (dangerous ones flagged), debuggable, allowBackup, components with exported/permission |
| `unity.il2cpp` | Metadata version and supported check |
| `strings.generic` | ASCII + UTF-16LE, section mapping, bounded scan |
| `signatures.rules` | Native YARA-subset engine + 12 default rules — see [SIGNATURES.md](SIGNATURES.md) |
| `heuristics.generic` | URLs/domains/IPs, shell command strings, base64 blobs, whole-file entropy, unknown kinds |

### Reports and UI

- `report.json` — `avero.report/v1`, deterministic (content-addressed evidence IDs, BTreeMap ordering).
- `report.md`, `report.html` — single-file HTML, dark theme, auto-escaped (XSS test included).
- Findings always reference evidence; reports include `coverage` and `unknowns`.
- Cache in `.avero/cache/<sha1>.json`; disable with `--no-cache`.
- **UI**: delegated to separate UI agents. The full specification is
  [UI-SPEC.md](UI-SPEC.md); the REST/SSE contract is
  [`avero.api/v1`](api/openapi.yaml) with a real sample report at
  [`docs/api/sample-report.json`](api/sample-report.json). No UI code lives in this goal.

### Local API (`avero serve`, `avero.api/v1`)

Implemented with a minimal blocking HTTP server (`tiny_http`), loopback-only, no
authentication (local single-user tool):

```powershell
target\release\avero.exe serve --port 8787
# GET  /api/health
# POST /api/scans              (multipart upload -> 202 job)
# GET  /api/jobs/{id}          GET /api/jobs/{id}/events   (SSE replay + stream)
# GET  /api/reports/{id}       (+ findings, evidence, sections, imports, exports,
#                                   strings, hex, apk-manifest, dotnet)
# POST /api/reports/{id}/decompile                        (ILSpyCmd sidecar)
# GET  /api/engines            POST /api/engines/{id}/install
# POST /api/diffs, GET .../disassembly                     (501 until implemented)
```

Verified end to end with `curl`: health, APK upload → scan job → done, report fetch,
`severity=high` finding filter, APK manifest facts, base64 hex slice, paged strings, engine
status, and SSE event replay. Results are persisted under `.avero/serve/` (git-ignored).

### Engine packs and decompilation

`engines/*.toml` describe Ghidra 12.2, rizin 0.9.1, ILSpyCmd 11.2.0.10050 and jadx 1.5.6.
The installer is functional:

- `avero engine install ilspycmd` — `dotnet tool install` into `engines/ilspycmd/<version>`.
- `avero engine pin rizin` — downloads the 11.7 MB archive, computes SHA-256, updates the manifest.
- `avero engine install rizin` — verifies SHA-256, extracts with `tar`, locates the binary.
- `avero engine install <id> --from <archive>` — offline/air-gapped installs.
- No HTTP dependency added: uses the OS `curl` and `tar`; manifest pinning uses `toml_edit`.

Verified end to end: rizin 0.9.1 installed and `rizin -v` reports `rizin 0.9.1 @ windows-x86-64`.
Also verified: `avero dotnet decompile SampleLib.dll --type SampleLib.Class1` produces
`SampleLib.Class1.decompiled.cs` via ILSpyCmd.

Details: [ENGINES.md](ENGINES.md).

### Native decompilation (`avero decompile`, P2)

Ghidra 12.2 is installed through the engine manager and driven by an embedded GhidraScript
(`src/ghidra_scripts/AveroExport.java`) via `analyzeHeadless`:

```powershell
avero engine pin ghidra
avero engine install ghidra                 # requires JDK 25+ (Ghidra 12.2)
avero decompile notepad.exe --limit 20 --out .\native-decompiled
avero decompile notepad.exe --function entry --limit 1 --json
```

Verified end to end on `notepad.exe` (x86:LE:64): 300 functions decompiled in one run,
per-function `.c` files plus `decompile.json`; `--function entry` produced the expected
`entry()` body. The same engine is available through the API:
`POST /api/reports/{id}/decompile` with `{"engine":"ghidra","type":"entry","limit":2}`
returns a job whose result contains the decompiled files. No Ghidra code is linked into the
binary (sidecar, Apache-2.0); JDK 25+ must be on `PATH`/`JAVA_HOME`.

---

## 3. Code layout

```
Cargo.toml
src/
  ir.rs probe.rs pehdr.rs zipscan.rs axml.rs hashing.rs evidence.rs findings.rs signatures.rs
  analyzers/{mod,pe,elf,macho,dotnet,apk,il2cpp,strings_analyzer,signatures_analyzer,heuristics}.rs
  pipeline.rs report.rs engine.rs main.rs
rules/avero-default.yar
tests/
  cli.rs (7) formats.rs (4) analyzers.rs (4) apk_manifest.rs (4)
  fixtures/sample.apk + AndroidManifest.bin   # generated by the project with aapt2
scripts/build.bat
.github/workflows/release.yml
engines/*.toml
docs/ research/
```

`cargo fmt` clean; release build ~45 s (incremental ~1–2 s).

---

## 4. Tests

```
44 unit (probe/hashing/evidence/findings/pehdr/zipscan/axml/strings/report/engine/signatures/server/decompile/util)
 7 CLI end-to-end
 4 format + determinism
 4 analyzer (ELF, Mach-O, signature match/clean)
 4 APK manifest (probe, AXML, analyzer facts/findings, zip inflate)
= 63 passing
```

Fixtures are generated by the project (the APK is built from our own manifest with
`aapt2`); no third-party binaries or malware are committed.

---

## 5. Known limitations

| Limitation | Plan |
|---|---|
| `.NET` assembly name/version not parsed yet (module name only) | P1.5 — full metadata table schema or ILSpyCmd sidecar |
| APK does not parse `resources.arsc` (resource names) or X.509 signing certificates | P3 — resource table + X.509 parsing |
| IL2CPP only reads the header; no type/method dump yet | P3 — metadata parser + Cpp2IL sidecar |
| Signature engine supports a YARA subset only | Extend gradually; YARA-X sidecar when rustc ≥ 1.95 |
| rizin disassembly adapter + `/disassembly` endpoint not wired yet; `avero decompile` uses Ghidra | P2 — rizin `pdj` adapter, API disassembly |
| No workbench UI or MCP server yet | P4–P5 |
| Binary is not code-signed (AV false positives possible) | P6 — code signing |

---

## 6. Development workflow

```powershell
scripts\build.bat build --release
scripts\build.bat test
cargo fmt

target\release\avero.exe scan "C:\Windows\System32\notepad.exe"
target\release\avero.exe apk sample.apk
target\release\avero.exe dotnet decompile SampleLib.dll --type SampleLib.Class1
```

When changing an analyzer, bump `impl Analyzer::version` if its output changes (the cache
key uses analyzer version + artifact hash + options). Use `--no-cache` while debugging.

Adding an analyzer:

1. Add a file under `src/analyzers/` implementing `Analyzer` (`id`, `accepts`, `priority`,
   `requires`, `run` → `Fragment`).
2. Do not print or render; every finding must carry evidence (`make_evidence`) and a confidence.
3. Register it in `builtin_analyzers()` and add tests.

---

## 7. Next steps (priority)

1. **rizin disassembly adapter** + `avero disasm` + native `/disassembly` API endpoint (P2).
2. **IL2CPP metadata dump** (types/methods/strings) + Cpp2IL adapter.
3. **APK `resources.arsc`** + signing-certificate parsing.
4. **`avero.api/v1` completions**: diff endpoint, richer engine-install coverage.
5. **MCP server** (bounded tools with evidence) — P5.
6. **Cross-platform CI matrix** (Linux/macOS builds) and code signing.

Out of scope for this goal: the workbench UI itself. UI agents own `apps/web` (or a separate
repository) and implement [UI-SPEC.md](UI-SPEC.md); this repository provides the contract,
sample data and the now-implemented API that it needs.
