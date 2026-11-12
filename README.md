# AveroDisassembler

> Fast, evidence-first Reverse Engineering workbench. **Native Rust binary — no Python, no runtime dependencies.**

[![CI](https://github.com/realkhoa/AveroDisassembler/actions/workflows/release.yml/badge.svg)](https://github.com/realkhoa/AveroDisassembler/actions/workflows/release.yml)
[![Release](https://img.shields.io/github/v/release/realkhoa/AveroDisassembler?sort=semver)](https://github.com/realkhoa/AveroDisassembler/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Status: v0.7.0 — Rust core + local API + Ghidra decompile** (P0/P1/P2). Static triage and
analysis for PE, .NET, ELF, Mach-O, APK (including the **binary AndroidManifest.xml**), Unity
IL2CPP, Godot PCK, firmware containers, scripts and WASM. Includes a **native signature
engine** (YARA subset), an **engine installer** (ILSpyCmd, rizin, Ghidra, jadx),
**`avero dotnet decompile`**, **native decompilation via Ghidra headless**
(`avero decompile`) and a **local REST/SSE API** (`avero serve`) for the workbench UI.
Every report is JSON/Markdown/HTML with verifiable evidence.

**UI is specified but not built here** — it is owned by separate UI agents. The complete
specification (screens, flows, data contracts, design system, milestones, acceptance
criteria) is in [docs/UI-SPEC.md](docs/UI-SPEC.md), with the API contract in
[docs/api/](docs/api/README.md). The API is implemented and can be exercised today.

## Why Rust?

The first prototype was written in Python and worked, but startup took ~450 ms, scanning
`notepad.exe` took ~2 s, and distribution required a Python interpreter plus a ~100 MB
venv. The Rust rewrite is a single 3.4 MB executable that scans the same file in ~111 ms
(cold) / ~20 ms (warm), with no runtime to install.

| Task | Python prototype | Rust 0.2 | **Rust 0.7** | Speed-up |
|---|---|---|---|---|
| `scan notepad.exe` (352 KB, cold) | 1,980 ms | 100 ms | **111 ms** | ~18× |
| `scan notepad.exe` (warm) | 1,070 ms | 18 ms | **20 ms** | ~53× |
| `scan APK` (with AXML parsing) | — | — | **38 ms** | — |
| CLI startup | ~450 ms | 13 ms | **11 ms** | ~40× |
| Distribution | venv + Python (~100 MB) | 2.74 MB | **3.79 MB** | — |
| Tests | 40 (pytest) | 38 | **63** | — |

> Measurements include ~10–13 ms of PowerShell process overhead; the binary itself is faster.

## Quickstart

```powershell
# Build once (Windows: scripts\build.bat initializes the MSVC environment)
scripts\build.bat build --release

# Triage + report
target\release\avero.exe scan "C:\Windows\System32\notepad.exe"
target\release\avero.exe scan sample.apk --out .\reports --json
target\release\avero.exe apk sample.apk
target\release\avero.exe probe sample.elf --json
target\release\avero.exe strings blob.bin -n 8

# Engines + decompilation
target\release\avero.exe engine install ilspycmd
target\release\avero.exe dotnet decompile SampleLib.dll --type SampleLib.Class1 --out .\decompiled
target\release\avero.exe engine install ghidra          # requires JDK 25+
target\release\avero.exe decompile notepad.exe --limit 20 --out .\native-decompiled
target\release\avero.exe engine install rizin
target\release\avero.exe engine list

# Local API for the AI/UI workbench (REST + SSE, loopback only)
target\release\avero.exe serve --port 8787

# Tests
scripts\build.bat test
```

Reports are written to `avero-out/<name>-<sha8>/report.{json,md,html}` by default.
Prebuilt binaries are attached to [GitHub Releases](https://github.com/realkhoa/AveroDisassembler/releases).

## Commands

| Command | Description |
|---|---|
| `scan <file>` | Triage + analyzers + JSON/MD/HTML report. `--json`, `--only/--skip`, `--no-cache`, `--no-md`, `--no-html` |
| `probe <file>` | Identify format, hashes, entropy and header metadata (no analyzers) |
| `strings <file>` | Extract ASCII/UTF-16LE (`-n`, `--limit`, `--unicode`, `--ascii`, `--json`) |
| `apk <file>` | Parse binary `AndroidManifest.xml`: package/version/SDK, permissions, debuggable, components (exported/permission); `--json` |
| `dotnet decompile <asm>` | Decompile an assembly or type with ILSpyCmd (`--type`, `--out`, `--json`) |
| `decompile <file>` | Native decompilation via Ghidra headless (`--function`, `--limit`, `--timeout`, `--out`, `--json`); requires Ghidra + JDK 25+ |
| `engine list/doctor` | Engine packs and local prerequisite checks |
| `engine install <id>` | Install an engine pack (zip + SHA-256, or `dotnet-tool`); `--from` for offline archives, `--force`, `--allow-unpinned` |
| `engine pin <id>` | Download the archive, compute SHA-256 and pin it in the manifest |
| `serve` | Local REST/SSE API (`avero.api/v1`) for the workbench UI: health, scans, jobs, reports, findings, evidence, strings, hex, APK manifest, .NET metadata, engines, decompile |
| `version` | Version and environment |

Exit codes: `0` success, `1` error.

## Formats & analyzers (9 analyzers)

| Format | Probe | Analyzer |
|---|---|---|
| PE / PE32+ | ✅ | ✅ `pe.structure`: sections+entropy, imports/exports, Rich header, overlay, ASLR/DEP/CFG, anti-debug/injection/network/crypto imports, timestamps |
| ELF | ✅ | ✅ `elf.structure`: sections+entropy, symbols/libraries, PIE/NX/RELRO/canary/fortify, W+X segments, executable stack, RPATH, debug info, static/stripped |
| Mach-O (thin/fat) | ✅ | ✅ `macho.structure`: segments/sections+entropy, dylibs, RPATH, code signature, FairPlay encryption, MH_PIE, W+X; universal binaries |
| .NET (CIL) | ✅ COR flags, AnyCPU/x86/x64 | ✅ `dotnet.metadata`: runtime `v4.0.30319`, CLR, module, type/method/field counts, TypeDef names, obfuscation heuristics (pure-Rust metadata parser) |
| APK / DEX / ZIP / JAR | ✅ | ✅ `apk.structure`: **AXML manifest** (package/version/SDK, permissions, debuggable, allowBackup, components exported/permission), unsigned, multidex, native libs, v1/v2-v3 signature, compression ratio |
| Unity IL2CPP metadata | ✅ | ✅ `unity.il2cpp`: metadata version and file facts |
| Any artifact | — | ✅ `signatures.rules`: **12 default rules** (UPX/packers/anti-debug/shell commands/persistence/credentials/base64 PE/AES S-box/obfuscators/VM/wallet/RMM) — see [docs/SIGNATURES.md](docs/SIGNATURES.md) |
| UnityFS / Godot PCK | ✅ | — (P3) |
| Firmware containers | ✅ squashfs/gzip/xz/bzip2/uImage/Android boot/UBI/UEFI | — (P3) |
| WASM / .pyc / script | ✅ | — |

Reports: canonical JSON (`avero.report/v1`, deterministic), Markdown, single-file HTML
(auto-escaped, dark theme). Every finding carries `evidence_ids`; every report includes
`coverage` and `unknowns`. Analysis cache is a JSON file store under `.avero/cache`.

## Architecture

```
src/
├─ ir.rs              avero.ir/v1 models (serde, BTreeMap for deterministic JSON)
├─ probe.rs           format detection (never executes the target)
├─ pehdr.rs           pure-Rust PE header parser (RVA→offset, sections)
├─ zipscan.rs         pure-Rust ZIP central-directory reader + entry inflate (APK)
├─ axml.rs            binary AndroidManifest.xml parser (UTF-8/UTF-16 string pools)
├─ signatures.rs      native YARA-subset engine + embedded rules
├─ hashing.rs         md5/sha1/sha256 + entropy in one pass
├─ evidence.rs        content-addressed evidence IDs (reproducible reports)
├─ findings.rs        content-addressed finding IDs
├─ analyzers/         pe, elf, macho, dotnet, apk, il2cpp, strings, signatures, heuristics
├─ pipeline.rs        priority/requires scheduling, file cache, fragment merge
├─ report.rs          JSON / Markdown / HTML renderers
├─ engine.rs          engine manifests + installer (download, SHA-256, extract, dotnet-tool)
└─ main.rs            CLI (clap + comfy-table + colored)
rules/avero-default.yar   # embedded signature rules
engines/*.toml            # engine manifests (engines themselves are not committed)
```

The target is never executed during scanning. Analyzers never print or render; all output
flows through `Fragment` → `Report`.

## Documentation

| Document | Contents |
|---|---|
| [Implementation status](docs/IMPLEMENTATION-STATUS.md) | What works, benchmarks, limitations, next steps |
| [UI specification](docs/UI-SPEC.md) | Screens, workflows, data contracts, design system, milestones and acceptance criteria for the UI agents |
| [API contract](docs/api/README.md) | `avero.api/v1` OpenAPI spec and sample `avero.report/v1` payload |
| [Engine packs](docs/ENGINES.md) | Installer, manifests, SHA-256 pinning, offline bundles, ILSpyCmd decompile |
| [Signature engine](docs/SIGNATURES.md) | Rule syntax, default ruleset, how to add rules |
| [Research report](docs/RE-RESEARCH-REPORT.md) | Survey of 112 open-source RE projects (2026-11-12 snapshot), licenses, market gaps, roadmap |
| [Technical design](docs/AVERO-DISASSEMBLER-DESIGN.md) | IR, analyzer protocol, pipeline, engine manager, CLI/API/MCP, security, testing |
| [License matrix](docs/THIRD-PARTY-ENGINES.md) | How third-party engines and Rust dependencies are integrated |
| [Research data](research/) | GitHub API snapshot, awesome lists, 112-repo metadata |

## CI / releases

`.github/workflows/release.yml` builds and tests on `windows-latest` for every push and
pull request. Pushing a `v*` tag creates a GitHub Release with the zipped executable and a
SHA-256 checksum. Local builds use `scripts/build.bat` (it calls `vcvars64.bat` first).

## Ethics & legal

Use this tool only on software you own or are authorized to analyze. Do not use it to
circumvent DRM, infringe copyright, or analyze malware outside an isolated environment.
See section 7 of the [research report](docs/RE-RESEARCH-REPORT.md).
