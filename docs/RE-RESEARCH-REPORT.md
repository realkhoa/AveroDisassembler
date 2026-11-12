# Research report: building a reverse-engineering “everything” tool

| | |
|---|---|
| **Project** | AveroDisassembler — evidence-first RE workbench |
| **Document** | Open-source landscape survey, gap analysis, architecture recommendation |
| **Data snapshot** | 2026-11-12 (Asia/Bangkok) |
| **Scope** | 112 open-source repositories, 4 awesome lists, 2 architecture references (REA, Ghidra ecosystem) |
| **Raw data** | [`research/repos-categorized.csv`](../research/repos-categorized.csv), [`research/repos.json`](../research/repos.json), [`research/sources/`](../research/sources/) |
| **Related** | [Technical design](AVERO-DISASSEMBLER-DESIGN.md) · [Implementation status](IMPLEMENTATION-STATUS.md) |

> Section 0 is the executive summary. Sections 1–5 are the survey and analysis. Sections 6–10 are the recommendation and plan.

---

## 0. Executive summary

1. **The open-source RE ecosystem is mature**: 95/112 surveyed projects were pushed within the last 365 days, 77/112 within the last 30 days. Engines are not missing — integration and user experience are.
2. **Ghidra is the default native decompiler** (99.6k stars, Apache-2.0, `Ghidra_12.2_build`). There is no technical reason to write a new decompiler from scratch.
3. **Do not build another “REA clone”**. REA (`morluto/rea`, MIT, `rea-agents-6.8.0`) already dominates the *CLI + MCP for agents* layer with ~453k stars. Wrapping engines behind an MCP server is now a commodity.
4. **The real gaps are**: (a) a unified workbench for native + .NET + mobile + game binaries; (b) game-engine verticals (IL2CPP/Unreal/Godot) with end-to-end workflows; (c) reproducible evidence/diff reports for CI; (d) offline, hash-pinned engine installation.
5. **The target machine had no RE tooling installed** (no Ghidra/rizin/x64dbg/Frida; Python had no capstone/LIEF/pefile/angr). A tool manager with offline engine packs is therefore a first-class feature, not an appendix.
6. **Licenses are architectural constraints**: 35 MIT + 18 Apache-2.0 + 18 NOASSERTION + 17 GPL-3.0 + 8 GPL-2.0 + 7 AGPL-3.0. Strategy: in-process for permissive licenses, sidecar processes for copyleft, never bundle commercial engines.
7. **Recommended stack**: a native core (originally prototyped in Python, implemented in Rust for speed and single-binary distribution), TypeScript/Next.js workbench UI, MCP server. Heavy engines run as sidecar processes (Ghidra headless, ILSpyCmd, jadx, Cpp2IL).
8. **An MVP is achievable in ~2 weeks**: CLI triage for PE/.NET/APK/IL2CPP + JSON/HTML reports with evidence + engine manager. The workbench UI follows.
9. **The biggest risk is scope**, not technology: define “everything” as an artifact × analysis-mode matrix and ship vertical slices.
10. **Five questions must be answered before continuing** (section 10): target verticals, CLI vs GUI first, core language, platforms, open-source/legal posture.

---

## 1. What “RE everything” means

No single tool does every cell well. A useful “everything” tool orchestrates several engines, normalises results and goes deep in a few strategic areas.

| Artifact \ Mode | Triage | Static (disasm/decompile) | Dynamic | Emulation/symbolic | Formats/extraction |
|---|---|---|---|---|---|
| PE / native Windows | DIE, PE-bear, capa, FLOSS, YARA | Ghidra, radare2/rizin, IDA/Binary Ninja | x64dbg, WinDbg, Frida, Speakeasy | angr, Triton, Unicorn, Qiling | LIEF, pefile |
| ELF / Mach-O / consoles | LIEF, `file` | Ghidra, rizin, RetDec | GDB/pwndbg/gef, Frida, QBDI | angr, Miasm, KLEE | LIEF, pyelftools |
| .NET (CIL) | DIE, AsmResolver, dnlib | dnSpyEx, ILSpy, AsmResolver | dnSpyEx debugger | — | dnfile, AsmResolver |
| Android (APK/DEX) | MobSF, androguard | jadx, Apktool, Recaf | Frida, objection | — | androguard, Apktool |
| Unity IL2CPP | Il2CppDumper, Cpp2IL | Cpp2IL → .NET → ILSpy | Frida | — | Il2CppDumper, AssetRipper |
| Unreal (UAB/PAK) | FModel, CUE4Parse | — | UE4SS | — | CUE4Parse |
| Godot (PCK) | GDRE Tools | GDRE (GDScript) | — | — | GDRE |
| Firmware/containers | binwalk, unblob, EMBA | Ghidra (rare arch), rizin | QEMU, firmadyne | — | unblob handlers, OFRAK |
| Bytecode runtimes | GoReSym, redress, pycdc | dedicated tools | Frida | — | per-runtime parsers |

**Pareto conclusion**: 80% of real-world needs (game modding, .NET apps, mobile) fall into five cells: PE native, .NET, Unity IL2CPP, Android APK, Unreal/Godot assets. The long tail only needs a path to a specialised engine.

## 2. Method and data quality

**Primary sources**

1. **GitHub GraphQL API** — 112 repositories with stars, forks, SPDX license, archived flag, `pushedAt`, latest release, primary language, description. Snapshot **2026-11-12**. Raw JSON in `research/sources/github-repos-{a,b,c}.json`.
2. **Awesome lists** — `morluto/awesome-reverse-engineering` (curated, 2026-10, includes maintenance caveats), `xiosec/Reverse-engineering`, `wtsxDev/reverse-engineering`, `tylerha97/awesome-reversing` (stored in `research/sources/`).
3. **Architecture references** — `morluto/rea` README + `package.json` (Java/Python/Swift bridges, built-in parsers), plus upstream descriptions for Ghidra/ImHex/Cutter.
4. **Target machine survey** — installed toolchain to check MVP feasibility (section 4.4).

**Caveats**

- Stars measure popularity, not quality (e.g. `binlex` with 606 stars is still a solid engine).
- `pushedAt` ≠ release activity.
- `NOASSERTION` means GitHub could not detect a license; read `LICENSE` before integrating.
- REA’s ~453k stars are unusually high; the number is reported as-is, not used as a quality metric.

## 3. Landscape (14 groups)

### 3.1 Native static engines

| Project | Stars | License | Notes |
|---|---:|---|---|
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | 99.6k | Apache-2.0 | Sleigh ISA descriptions, P-Code IR, headless analyzer, BSim, PyGhidra. Default decompiler. |
| [radare2](https://github.com/radareorg/radare2) | 25.4k | LGPL-3.0 | Command-oriented CLI, JSON output (`-j`), `r2pipe`; ideal for batch/scripting. |
| [rizin](https://github.com/rizinorg/rizin) + [Cutter](https://github.com/rizinorg/cutter) | 4.2k + 20.2k | LGPL-3.0 / GPL-3.0 | Clean radare2 fork; Cutter is a Qt GUI. |
| [RetDec](https://github.com/avast/retdec) | 8.7k | MIT | LLVM-based decompiler, `v5.0` (2026-05) but limited maintenance. |
| [rev.ng](https://github.com/revng/revng) | 1.8k | GPL-2.0 | QEMU+LLVM lifting framework, heavy build. |
| [Snowman](https://github.com/yegord/snowman) | 2.2k | NOASSERTION | Standalone decompiler, archived 2023. |

**Conclusion**: Ghidra for decompilation; rizin/radare2 for batch/JSON; do not write a decompiler.

### 3.2 Foundation libraries

| Project | Stars | License | Role |
|---|---:|---|---|
| [Capstone](https://github.com/capstone-engine/capstone) | 9.2k | BSD-3-Clause | Multi-architecture disassembler library. |
| [Zydis](https://github.com/zyantific/zydis) | 4.4k | MIT | Fast x86/x64 decode/encode. |
| [Keystone](https://github.com/keystone-engine/keystone) | 2.7k | GPL-2.0 (dual commercial) | Assembler; sidecar unless GPL is acceptable. |
| [Unicorn](https://github.com/unicorn-engine/unicorn) | 9.6k | GPL-2.0 | CPU emulator; sidecar. |
| [LIEF](https://github.com/lief-project/LIEF) | 5.7k | Apache-2.0 | PE/ELF/Mach-O/DEX parsing and modification, `1.0.0`. |
| [ImHex](https://github.com/WerWolv/ImHex) | 55.8k | GPL-2.0 | Hex editor + pattern DSL + plugin SDK. |
| [Kaitai Struct](https://github.com/kaitai-io/kaitai_struct) | 4.7k | NOASSERTION | Declarative format descriptions generating parsers. |
| [YARA](https://github.com/VirusTotal/yara) / [YARA-X](https://github.com/VirusTotal/yara-x) | 10.0k / 1.4k | BSD-3-Clause | Pattern scanning; YARA 4.x in maintenance, YARA-X successor. |

### 3.3 Debuggers

[x64dbg](https://github.com/x64dbg/x64dbg) (50.3k, GPL-3.0), [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) (free, official MCP server since 1.2610.1001.0), [pwndbg](https://github.com/pwndbg/pwndbg) / [GEF](https://github.com/hugsy/gef) (MIT), [System Informer](https://github.com/winsiderss/systeminformer) (16.5k, MIT), [Cheat Engine](https://github.com/cheat-engine/cheat-engine) (19.5k, license needs checking), [ReClass.NET](https://github.com/ReClassNET/ReClass.NET) (2.2k, MIT).

### 3.4 Dynamic instrumentation

[Frida](https://github.com/frida/frida) (22.8k, `17.26.2`), [DynamoRIO](https://github.com/DynamoRIO/dynamorio) (3.2k), [QBDI](https://github.com/QBDI/QBDI) (1.8k), [Panda](https://github.com/panda-re/panda) (2.8k), [TinyTracer](https://github.com/hasherezade/tiny_tracer) (1.7k), [r2frida](https://github.com/nowsecure/r2frida) (1.5k), [objection](https://github.com/sensepost/objection) (9.5k).

### 3.5 Symbolic execution, lifting and SMT

[angr](https://github.com/angr/angr) (9.4k, BSD-2), [Triton](https://github.com/JonathanSalwan/Triton) (4.4k, Apache-2.0), [Miasm](https://github.com/cea-sec/miasm) (4.0k, GPL-2.0), [KLEE](https://github.com/klee/klee) (3.0k), [BINSEC](https://github.com/binsec/binsec) (435), [Z3](https://github.com/Z3Prover/z3) (12.9k, MIT), [BAP](https://github.com/BinaryAnalysisPlatform/bap) (2.3k, MIT), [Remill](https://github.com/lifting-bits/remill) (1.9k, Apache-2.0); McSema is archived (2022).

### 3.6 Emulation and sandboxes

[Speakeasy](https://github.com/mandiant/speakeasy) (2.1k, MIT), [Qiling](https://github.com/qilingframework/qiling) (6.2k, GPL-2.0), [CAPEv2](https://github.com/kevoreilly/CAPEv2) (3.7k, GPL-3.0), [Dumpulator](https://github.com/mrexodia/dumpulator) (895, BSL-1.0), [mwemu](https://github.com/mwemuorg/mwemu) (321, Apache-2.0).

### 3.7 Triage and extraction

[Detect It Easy](https://github.com/horsicq/Detect-It-Easy) (11.9k, MIT), [PE-bear](https://github.com/hasherezade/pe-bear) (3.9k, GPL-2.0), [capa](https://github.com/mandiant/capa) (6.3k, Apache-2.0, `v10.0.0`), [FLOSS](https://github.com/mandiant/flare-floss) (4.2k, Apache-2.0), [binwalk](https://github.com/ReFirmLabs/binwalk) (14.7k, MIT, Rust v3), [unblob](https://github.com/onekey-sec/unblob) (2.6k, MIT).

### 3.8 .NET, Java and Android

[dnSpyEx](https://github.com/dnSpyEx/dnSpy) (11.5k, GPL-3.0, `v6.6.0`; original dnSpy archived), [ILSpy](https://github.com/icsharpcode/ILSpy) (27.0k, MIT, `v11.2`), [AsmResolver](https://github.com/Washi1337/AsmResolver) (1.1k, MIT), [dnlib](https://github.com/0xd4d/dnlib) (2.5k, MIT), [Mono.Cecil](https://github.com/jbevain/cecil) (3.0k, MIT), [de4dot](https://github.com/de4dot/de4dot) (archived 2020). Android: [jadx](https://github.com/skylot/jadx) (51.8k, Apache-2.0, `v1.5.6`), [Apktool](https://github.com/iBotPeaches/Apktool) (27.2k, Apache-2.0, `v3.0.3`), [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) (22.2k, GPL-3.0), [androguard](https://github.com/androguard/androguard) (6.4k, Apache-2.0), [Recaf](https://github.com/Col-E/Recaf), [Vineflower](https://github.com/Vineflower/vineflower), [CFR](https://github.com/leibnitz27/cfr).

### 3.9 Runtime and bytecode

[GoReSym](https://github.com/mandiant/GoReSym) (1.1k, MIT), [redress](https://github.com/goretk/redress) (1.2k, AGPL-3.0), [pycdc](https://github.com/zrax/pycdc) (4.7k, GPL-3.0), [uncompyle6](https://github.com/rocky/python-uncompyle6) (4.3k), [PyLingual](https://github.com/syssec-utd/pylingual) (1.4k), [hermes-dec](https://github.com/P1sec/hermes-dec) (1.2k, AGPL-3.0), [reFlutter](https://github.com/Impact-I/reFlutter) / [blutter](https://github.com/worawit/blutter) (2.8k each), [ipsw](https://github.com/blacktop/ipsw) (3.9k, MIT), [unluac](https://github.com/HansWessels/unluac) (260, 2015).

### 3.10 Firmware

[EMBA](https://github.com/e-m-b-a/emba) (3.8k, GPL-3.0), [FACT_core](https://github.com/fkie-cad/FACT_core) (1.5k, GPL-3.0), [firmadyne](https://github.com/firmadyne/firmadyne) (2.1k, MIT, dormant), [OFRAK](https://github.com/redballoonsecurity/ofrak) (2.1k), [avatar2](https://github.com/avatartwo/avatar2) (586, Apache-2.0).

### 3.11 Game reverse engineering

[Cpp2IL](https://github.com/SamboyCoding/Cpp2IL) (3.1k, MIT, active) vs [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) (9.6k, MIT, last push 2024-08) vs [Il2CppInspector](https://github.com/djkaty/Il2CppInspector) (3.1k, AGPL-3.0, last push 2022). Assets: [AssetRipper](https://github.com/AssetRipper/AssetRipper) (8.9k, GPL-3.0, `2.0.0`), [AssetStudio](https://github.com/Perfare/AssetStudio) (archived 2022). Unreal: [FModel](https://github.com/4sval/FModel) (3.4k, GPL-3.0), [CUE4Parse](https://github.com/FabianFG/CUE4Parse) (687, Apache-2.0), [UE4SS](https://github.com/UE4SS-RE/RE-UE4SS) (3.2k, MIT), [UAssetGUI](https://github.com/atenfyr/UAssetGUI). Godot: [GDRE Tools](https://github.com/GDRETools/gdsdecomp) (4.4k, MIT). Source 2: [ValveResourceFormat](https://github.com/ValveResourceFormat/ValveResourceFormat) (2.6k, MIT).

### 3.12 Binary diffing

[BinDiff](https://github.com/google/bindiff) (3.2k, Apache-2.0, `v8`) + [BinExport](https://github.com/google/binexport), [Diaphora](https://github.com/joxeankoret/diaphora) (4.5k, AGPL-3.0), [ghidriff](https://github.com/clearbluejar/ghidriff) (822, GPL-3.0), [Binlex](https://github.com/c3rb3ru5d3d53c/binlex) (606, MIT).

### 3.13 AI-assisted analysis and MCP

[REA](https://github.com/morluto/rea) (453k, MIT, MCP + CLI, bridges to Hopper/Ghidra/IDA/Cutter/JADX, built-in parsers for PE/ELF/Mach-O, IL2CPP metadata, Godot PCK, Go, Rust, GPU code objects, model artifacts; Node ≥ 22.23.4), [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) (13.4k, MIT), [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) (11.9k, Apache-2.0), [ghidra-mcp](https://github.com/bethington/ghidra-mcp) (6.2k), [ida-mcp](https://github.com/HexRaysSA/ida-mcp) (1.6k, MIT, official Hex-Rays), [radare2-mcp](https://github.com/radareorg/radare2-mcp) (360, MIT), [Gepetto](https://github.com/JusticeRage/Gepetto) (3.5k, GPL-3.0). Commercial products now ship MCP servers (Binary Ninja, WinDbg), confirming the agent-native trend.

### 3.14 Architecture lessons

| Project | Lesson | Applied in Avero |
|---|---|---|
| Ghidra | Separate ISA description (Sleigh) from analysis; P-Code IR; headless mode | Engine adapter + own IR; headless-friendly |
| radare2/rizin | Everything is a command, every output has JSON (`-j`), pipeable | Machine-readable JSON first |
| Cutter | GUI separated from engine by API/IPC | Workbench will talk to the core over REST/WS |
| ImHex | Pattern DSL + plugin SDK + community patterns | Format DSL + plugin SDK planned |
| BinDiff/BinExport | Exporter separated from differ; protobuf interchange | `avero.ir/v1` stable schema |
| angr | IR-first, hooks, composable analyses | Composable analyzers, `requires` dependencies |
| REA | MCP-first, per-engine bridges, evidence + limitations, bounded outputs | Evidence-first reports, bounded tool outputs |
| unblob | Handler registry + recursive extraction + limits | Extraction pipeline with depth/size limits |
| MobSF | API-first + report + static/dynamic orchestration | REST API + report engine (planned) |

## 4. Quantitative analysis (2026-11-12 snapshot)

### 4.1 Maintenance

| Metric | Value |
|---|---|
| Repositories surveyed | **112** |
| Pushed in last 30 days | **77 / 112 (68.8%)** |
| Pushed in last 90 days | **88 / 112 (78.6%)** |
| Pushed in last 365 days | **95 / 112 (84.8%)** |
| No push for >365 days | **17** (dnSpy, de4dot, McSema, AssetStudio, Il2CppInspector, Snowman, Cheat Engine, ScyllaHide, dex2jar, Il2CppDumper, Zygisk-Il2CppDumper, ReClass.NET, firmadyne, Dumpulator, avatar2, malduck, unluac) |
| Archived | **5** (dnSpy, AssetStudio, de4dot, McSema, Snowman) |

Many classic tutorial tools (dnSpy, de4dot, AssetStudio, Il2CppDumper) are stale; new projects must map to successors (dnSpyEx, ILSpy, AssetRipper, Cpp2IL) and surface maintenance warnings.

### 4.2 License distribution

| License | Repositories | Integration strategy |
|---|---:|---|
| MIT | 35 | In-process, attribution |
| Apache-2.0 | 18 | In-process, NOTICE + patent grant |
| NOASSERTION | 18 | Read LICENSE manually before integrating |
| GPL-3.0 | 17 | Sidecar/process only |
| GPL-2.0 | 8 | Sidecar (Unicorn, Keystone, Miasm, Qiling, rev.ng…) |
| AGPL-3.0 | 7 | Strongest copyleft; sidecar, avoid shipping in commercial builds |
| BSD-2/3-Clause | 6 | In-process, attribution |
| LGPL-2.1/3.0 | 2 | Dynamic linking or sidecar |
| BSL-1.0 | 1 | Read terms (Dumpulator) |

### 4.3 Languages and scale

Python 29, C++ 22, C 16, C# 16, Java 11, Rust 4, Shell 3, Go 3, TypeScript 2, OCaml 2. 25 repositories have ≥10k stars; 102/112 have ≥1k; median ≈3.9k.

### 4.4 Target machine survey

| Component | Status | Design impact |
|---|---|---|
| OS | Windows 11 build 26200, 32 GB RAM, 16 logical cores | Ghidra/JVM feasible |
| .NET | SDK 10.0.302 | C# sidecars (ILSpyCmd, Cpp2IL) available |
| Python | 3.13.14 + `uv` | Not needed by the Rust core |
| Node | 22.22.0 | Below REA’s requirement (≥22.23.4) |
| Java | JDK 21 | Ghidra, jadx, Apktool, Cutter |
| Go / Rust / CMake / git / gh / adb | Available | Build tooling + Android workflows |
| RE engines installed | **None** | Engine manager is a first-class feature |
| MSVC linker | Visual Studio 18 Community + Windows SDK | Rust MSVC builds via `vcvars64.bat` |

## 5. Market gaps and opportunities

| Capability | Ghidra | IDA Pro | Binary Ninja | radare2/Cutter | REA | **Avero** |
|---|---|---|---|---|---|---|
| Native disasm/decompile | ● | ● | ● | ◐ | ◐ | ● (Ghidra later) |
| Debug/dynamic | ◐ | ● | ● | ◐ | ◐ | ◐ (planned) |
| .NET / CIL | ○ | ◐ | ◐ | ○ | ◐ | ● |
| Android/APK | ○ | ◐ | ○ | ○ | ● | ● |
| Unity IL2CPP | ○ | ◐ | ○ | ○ | ● | ◐ (header; dump planned) |
| Unreal/Godot assets | ○ | ○ | ○ | ○ | ◐ | ○ (planned) |
| Binary diff | ○ | ◐ | ◐ | ◐ | ○ | ○ (planned) |
| AI/agent (MCP) | ◐ | ● | ● | ● | ●● | ● (planned) |
| GUI workbench | ● | ● | ● | ◐ | ○ | ○ (planned) |
| Offline/air-gapped | ● | ● | ◐ | ● | ◐ | ● (engine packs) |
| Free/OSS | ● | ○ | ○ | ● | ● | ● |
| Reproducible evidence reports | ◐ | ◐ | ◐ | ○ | ◐ | ● |

**Eight concrete gaps**

1. No single OSS workbench for native + .NET + mobile + game binaries.
2. Game-engine verticals are fragmented (IL/asset/format tools do not share a type model).
3. Most tools produce text/HTML without provenance; AI agents cannot verify claims.
4. Onboarding is poor: clean machines have no engines, and installing Ghidra/JDK/CLI tools is error-prone.
5. License fragmentation makes “bundle everything” legally risky; no clean sidecar + attribution story.
6. Little localised documentation/UX outside English.
7. No unified plugin SDK (Ghidra Java, r2 C/JS, IDA C++, ImHex C++).
8. No “binary regression testing” for game patches (automatic diff + change report).

**Positioning**: *an orchestrator + unified IR + evidence + workbench, built on the best OSS engines, going deep in game/.NET/mobile verticals, shipped offline, agent-compatible via MCP.*

## 6. Product recommendation

**Vision**: “Drop any file → within 60 seconds know what it is, how it was built, what stands out, and drill down to functions/IL/assets with verifiable evidence.”

Eight design principles:

1. Do not reimplement engines (except where no usable OSS exists — e.g. a current IL2CPP parser).
2. Machine-readable first: one IR feeding CLI/UI/MCP.
3. Evidence is mandatory for every finding.
4. License-tiered integration: permissive in-process, copyleft sidecar.
5. Offline-first, pinned engines with SHA-256.
6. Never execute the target by default.
7. Bounded and safe: size/depth/time limits, no shell injection.
8. Vertical-first: each phase ships an end-to-end workflow.

**Stack decision**: after prototyping in Python (fast validation, but slow startup and heavy distribution), the core was implemented in **Rust**: single binary, ~11 ms startup, no runtime. The UI will be TypeScript/Next.js (planned); heavy engines are sidecars. A .NET/Avalonia desktop build remains a fallback if .NET/Unity depth becomes the priority.

**Roadmap**: P0 probe + IR + CLI; P1 PE/.NET/ELF/Mach-O/APK/signatures; P2 engine installer + Ghidra/rizin adapters; P3 IL2CPP/mobile assets; P4 workbench UI; P5 MCP + REST + diff; P6 code signing and cross-platform CI. See [implementation status](IMPLEMENTATION-STATUS.md).

## 7. Licenses and legal considerations

- **Permissive** libraries may be linked; keep notices.
- **LGPL** requires dynamic linking/replaceability; sidecars are safer.
- **GPL/AGPL** must remain sidecar processes; distributing binaries requires source and license compliance. AGPL is the highest risk for hosted services.
- **Commercial tools** (IDA, Binary Ninja, Hopper, Malcat) must never be bundled; adapters work only with the user’s own license.

Legal/ethical notes (Vietnam and international): only analyze software you own or are authorised to analyze; do not circumvent DRM; respect game/app EULAs; run malware only in isolated environments. See the disclaimers in the README and third-party matrix.

## 8. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Scope creep | High | Very high | Artifact/mode matrix, phase gates, non-goals |
| License contamination | Medium | High | Sidecar-only copyleft, CI license scans, third-party matrix |
| Engine fragility | High | Medium | Pin versions, contract tests, fallback engines |
| AV/EDR false positives | High | Medium | No shellcode packing, code signing, documented behaviour |
| AI hallucination | High | High | Evidence gate: no evidence → no conclusion |
| Malformed files crashing the tool | Medium | High | Bounds-checked parsers, fuzzing, per-analyzer isolation |
| Installer size (Ghidra + JDK) | High | Medium | Optional engine packs, offline bundles |
| Maintainer bandwidth | High | High | Plugin SDK, community adapters, pinned official adapters |

## 9. Immediate plan (next 7 days)

1. Answer the five questions in section 10.
2. Set up CI (build + test + release artifacts) — done in v0.5.0.
3. Finish the Ghidra headless adapter and `avero decompile`.
4. Add IL2CPP metadata dumping (types/methods) and test on a real game.
5. Add `resources.arsc` parsing and signing-certificate inspection for APK.
6. Build the workbench UI spike (report viewer + hex + findings/evidence).
7. Add fuzz targets for PE/ZIP/AXML parsers.

## 10. Five questions before continuing

1. **Primary vertical**: game modding (Unity/Unreal/Godot), .NET apps, malware triage, or mobile?
2. **First surface**: CLI + reports (fast) or workbench GUI (differentiating)?
3. **Core language**: accept the Rust core (fast, single binary) or prefer .NET/Avalonia?
4. **Priority platforms**: Windows only, or Windows + Android + Linux?
5. **Release posture**: private tool, or public open source (license hygiene, code signing, disclaimers)?

---

## References

- GitHub REST/GraphQL API — 2026-11-12 snapshot, 112 repositories (`research/sources/`).
- [morluto/awesome-reverse-engineering](https://github.com/morluto/awesome-reverse-engineering) — curated list with maintenance caveats.
- [morluto/rea](https://github.com/morluto/rea) — README and `package.json` (MCP/bridge architecture).
- [xiosec/Reverse-engineering](https://github.com/xiosec/Reverse-engineering), [wtsxDev/reverse-engineering](https://github.com/wtsxDev/reverse-engineering), [tylerha97/awesome-reversing](https://github.com/tylerha97/awesome-reversing).
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) · [radare2](https://github.com/radareorg/radare2) · [rizin](https://github.com/rizinorg/rizin) · [Cutter](https://github.com/rizinorg/cutter) · [RetDec](https://github.com/avast/retdec) · [rev.ng](https://github.com/revng/revng)
- [Capstone](https://github.com/capstone-engine/capstone) · [LIEF](https://github.com/lief-project/LIEF) · [Zydis](https://github.com/zyantific/zydis) · [Unicorn](https://github.com/unicorn-engine/unicorn) · [Keystone](https://github.com/keystone-engine/keystone) · [ImHex](https://github.com/WerWolv/ImHex) · [Kaitai](https://kaitai.io/)
- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) · [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) · [ida-mcp](https://github.com/HexRaysSA/ida-mcp) · [radare2-mcp](https://github.com/radareorg/radare2-mcp) · [Gepetto](https://github.com/JusticeRage/Gepetto) · [Binary Ninja MCP](https://docs.binary.ninja/guide/mcp.html) · [WinDbg MCP](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/set-up-windbg-mcp)
- [dnSpyEx](https://github.com/dnSpyEx/dnSpy) · [ILSpy](https://github.com/icsharpcode/ILSpy) · [AsmResolver](https://github.com/Washi1337/AsmResolver) · [jadx](https://github.com/skylot/jadx) · [Apktool](https://github.com/iBotPeaches/Apktool) · [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) · [Cpp2IL](https://github.com/SamboyCoding/Cpp2IL) · [AssetRipper](https://github.com/AssetRipper/AssetRipper) · [FModel](https://github.com/4sval/FModel) · [CUE4Parse](https://github.com/FabianFG/CUE4Parse) · [UE4SS](https://github.com/UE4SS-RE/RE-UE4SS) · [GDRE](https://github.com/GDRETools/gdsdecomp)
- [Frida](https://github.com/frida/frida) · [x64dbg](https://github.com/x64dbg/x64dbg) · [angr](https://github.com/angr/angr) · [Triton](https://github.com/JonathanSalwan/Triton) · [Miasm](https://github.com/cea-sec/miasm) · [Z3](https://github.com/Z3Prover/z3) · [capa](https://github.com/mandiant/capa) · [FLOSS](https://github.com/mandiant/flare-floss) · [DIE](https://github.com/horsicq/Detect-It-Easy) · [PE-bear](https://github.com/hasherezade/pe-bear) · [binwalk](https://github.com/ReFirmLabs/binwalk) · [unblob](https://github.com/onekey-sec/unblob) · [EMBA](https://github.com/e-m-b-a/emba) · [BinDiff](https://github.com/google/bindiff) · [BinExport](https://github.com/google/binexport) · [ghidriff](https://github.com/clearbluejar/ghidriff)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3) · [MemProcFS](https://github.com/ufrisk/MemProcFS) · [PE-sieve](https://github.com/hasherezade/pe-sieve) · [Speakeasy](https://github.com/mandiant/speakeasy) · [Qiling](https://github.com/qilingframework/qiling) · [CAPEv2](https://github.com/kevoreilly/CAPEv2)
