# Third-party licenses

| | |
|---|---|
| **Purpose** | Define how each open-source engine is integrated into AveroDisassembler without violating its license |
| **Snapshot** | GitHub API 2026-11-12 (`research/repos-categorized.csv`) |
| **Note** | Technical analysis, **not legal advice**. Before a commercial release, have counsel review and read each upstream LICENSE. |

## General rules

1. **Permissive (MIT / BSD / Apache-2.0)** → may be linked in-process; keep copyright and
   LICENSE notices, add a NOTICE for Apache, list attribution in `THIRD-PARTY.md`/About UI.
2. **LGPL** → dynamic linking or sidecar process; users must be able to replace the library;
   avoid static linking unless GPL-like terms are acceptable.
3. **GPL / AGPL** → **sidecar process only**, communicating via CLI/JSON; never import or
   link into the core; if redistributing binaries, include corresponding source and license.
   For AGPL, avoid exposing it as a public service without understanding the obligations.
4. **NOASSERTION** → treat as copyleft until the LICENSE file is read; do not bundle.
5. **Commercial (IDA, Binary Ninja, Hopper, Malcat)** → never bundle; adapters work only
   when the user has their own license.
6. **Do not copy engine source** into this repository unless the license allows it and
   attribution is provided; prefer public APIs/CLI.

## Integration matrix

| Engine | Repo | License (API) | Integration | Main obligations |
|---|---|---|---|---|
| Ghidra | NationalSecurityAgency/ghidra | Apache-2.0 | Sidecar `analyzeHeadless` + export script | NOTICE, attribution |
| radare2 | radareorg/radare2 | NOASSERTION → LGPL-3.0 | Sidecar `-j` JSON | LGPL |
| rizin | rizinorg/rizin | LGPL-3.0 | Sidecar | LGPL |
| Cutter | rizinorg/cutter | GPL-3.0 | Never linked; UX reference only | GPL if distributed |
| Capstone | capstone-engine/capstone | NOASSERTION → BSD-3 | In-process (optional) | Attribution |
| Zydis | zyantific/zydis | MIT | In-process/sidecar | Attribution |
| Keystone | keystone-engine/keystone | GPL-2.0 | Sidecar only (or commercial license) | GPL-2.0 |
| Unicorn | unicorn-engine/unicorn | GPL-2.0 | Sidecar only | GPL-2.0 |
| LIEF | lief-project/LIEF | Apache-2.0 | In-process (future) | NOTICE |
| ImHex | WerWolv/ImHex | GPL-2.0 | External application only | GPL |
| Kaitai Struct | kaitai-io/kaitai_struct | NOASSERTION | Spec import → generated parser | Check compiler/runtime license |
| YARA-X | VirusTotal/yara-x | BSD-3-Clause | Not used yet (rustc ≥ 1.95 + wasmtime); sidecar later | Attribution |
| YARA | VirusTotal/yara | BSD-3-Clause | Legacy/sidecar | Attribution |
| ILSpy / ilspycmd | icsharpcode/ILSpy | MIT | Sidecar (installed by `avero engine install ilspycmd`) | Attribution |
| dnSpyEx | dnSpyEx/dnSpy | GPL-3.0 | Sidecar (external app) | GPL-3.0 |
| AsmResolver | Washi1337/AsmResolver | MIT | C# sidecar | Attribution |
| dnlib | 0xd4d/dnlib | MIT | C# sidecar | Attribution |
| Mono.Cecil | jbevain/cecil | MIT | C# sidecar | Attribution |
| jadx | skylot/jadx | Apache-2.0 | Sidecar (zip engine pack) | NOTICE |
| Apktool | iBotPeaches/Apktool | Apache-2.0 | Sidecar | NOTICE |
| androguard | androguard/androguard | Apache-2.0 | In-process (future, no Python requirement) | NOTICE |
| MobSF | MobSF/Mobile-Security-Framework-MobSF | GPL-3.0 | External service | GPL-3.0 |
| Cpp2IL | SamboyCoding/Cpp2IL | MIT | Sidecar (.NET) | Attribution |
| Il2CppDumper | Perfare/Il2CppDumper | MIT | Sidecar (slow upstream) | Attribution |
| AssetRipper | AssetRipper/AssetRipper | GPL-3.0 | Sidecar only | GPL-3.0 |
| AssetStudio | Perfare/AssetStudio | MIT | Archived — not used | — |
| FModel | 4sval/FModel | GPL-3.0 | Never bundled | GPL-3.0 |
| CUE4Parse | FabianFG/CUE4Parse | Apache-2.0 | Sidecar (.NET) | NOTICE |
| UE4SS | UE4SS-RE/RE-UE4SS | MIT | Runtime plugin installed by user | Attribution |
| UAssetGUI | atenfyr/UAssetGUI | MIT | Sidecar | Attribution |
| GDRE Tools | GDRETools/gdsdecomp | MIT | Sidecar | Attribution |
| ValveResourceFormat | ValveResourceFormat/ValveResourceFormat | MIT | Sidecar | Attribution |
| binwalk | ReFirmLabs/binwalk | MIT | Sidecar | Attribution |
| unblob | onekey-sec/unblob | MIT | Sidecar | Attribution |
| EMBA | e-m-b-a/emba | GPL-3.0 | Sidecar | GPL-3.0 |
| FACT_core | fkie-cad/FACT_core | GPL-3.0 | Never bundled | GPL-3.0 |
| OFRAK | redballoonsecurity/ofrak | NOASSERTION | Sidecar; read LICENSE first | Check |
| angr | angr/angr | BSD-2-Clause | External/optional analysis service | Attribution |
| Triton | JonathanSalwan/Triton | Apache-2.0 | In-process (future C++ binding) | NOTICE |
| Miasm | cea-sec/miasm | GPL-2.0 | Sidecar only | GPL-2.0 |
| Z3 | Z3Prover/z3 | NOASSERTION → MIT | In-process (future) | Attribution |
| BAP | BinaryAnalysisPlatform/bap | MIT | Sidecar (OCaml) | Attribution |
| Remill | lifting-bits/remill | Apache-2.0 | Sidecar | NOTICE |
| Frida | frida/frida | NOASSERTION → LGPL-2.1/wxWindows | Sidecar runtime agent | LGPL |
| DynamoRIO | DynamoRIO/dynamorio | NOASSERTION → BSD-style | Sidecar | Check |
| QBDI | QBDI/QBDI | NOASSERTION → Apache-2.0 | Sidecar | Check |
| x64dbg | x64dbg/x64dbg | NOASSERTION → GPL-3.0 | External app / automation | GPL-3.0 |
| ScyllaHide | x64dbg/ScyllaHide | GPL-3.0 | x64dbg plugin installed by user | GPL-3.0 |
| PE-sieve | hasherezade/pe-sieve | BSD-2-Clause | Sidecar | Attribution |
| HollowsHunter | hasherezade/hollows_hunter | BSD-2-Clause | Sidecar | Attribution |
| System Informer | winsiderss/systeminformer | MIT | External app | Attribution |
| Speakeasy | mandiant/speakeasy | MIT | External Python service (optional) | Attribution |
| Qiling | qilingframework/qiling | GPL-2.0 | Sidecar only | GPL-2.0 |
| Dumpulator | mrexodia/dumpulator | BSL-1.0 | Sidecar; read terms | BSL |
| mwemu | mwemuorg/mwemu | Apache-2.0 | Sidecar | NOTICE |
| CAPEv2 | kevoreilly/CAPEv2 | NOASSERTION → GPL-3.0 | External service | GPL-3.0 |
| Volatility 3 | volatilityfoundation/volatility3 | NOASSERTION → GPL-2.0 | Sidecar | GPL-2.0 |
| MemProcFS | ufrisk/MemProcFS | AGPL-3.0 | Sidecar only | AGPL-3.0 |
| PCILeech | ufrisk/pcileech | AGPL-3.0 | Never bundled | AGPL-3.0 |
| Detect It Easy | horsicq/Detect-It-Easy | MIT | Sidecar/in-process | Attribution |
| PE-bear | hasherezade/pe-bear | GPL-2.0 | External app | GPL-2.0 |
| capa | mandiant/capa | Apache-2.0 | External Python service (optional) | NOTICE |
| FLOSS | mandiant/flare-floss | Apache-2.0 | Sidecar | NOTICE |
| BinDiff | google/bindiff | Apache-2.0 | Sidecar | NOTICE |
| BinExport | google/binexport | Apache-2.0 | Sidecar | NOTICE |
| Diaphora | joxeankoret/diaphora | AGPL-3.0 | Sidecar/IDA plugin | AGPL-3.0 |
| ghidriff | clearbluejar/ghidriff | GPL-3.0 | Pipeline reference only | GPL-3.0 |
| Binlex | c3rb3ru5d3d53c/binlex | MIT | Sidecar | Attribution |
| GoReSym | mandiant/GoReSym | MIT | Sidecar | Attribution |
| redress | goretk/redress | AGPL-3.0 | Sidecar only | AGPL-3.0 |
| pycdc | zrax/pycdc | GPL-3.0 | Sidecar | GPL-3.0 |
| PyLingual | syssec-utd/pylingual | GPL-3.0 | Sidecar | GPL-3.0 |
| hermes-dec | P1sec/hermes-dec | AGPL-3.0 | Sidecar | AGPL-3.0 |
| reFlutter | Impact-I/reFlutter | GPL-3.0 | Sidecar | GPL-3.0 |
| blutter | worawit/blutter | MIT | Sidecar | Attribution |
| ipsw | blacktop/ipsw | MIT | Sidecar | Attribution |
| REA | morluto/rea | MIT | Optional MCP integration | Attribution |
| GhidraMCP | LaurieWired/GhidraMCP | Apache-2.0 | Optional plugin | NOTICE |
| ida-pro-mcp | mrexodia/ida-pro-mcp | MIT | Optional, requires IDA license | Attribution |
| ida-mcp | HexRaysSA/ida-mcp | MIT | Optional, requires IDA license | Attribution |
| radare2-mcp | radareorg/radare2-mcp | MIT | Optional | Attribution |
| Gepetto | JusticeRage/Gepetto | GPL-3.0 | Idea reference only | GPL-3.0 |
| Cheat Engine | cheat-engine/cheat-engine | NOASSERTION | External app | Check |
| ReClass.NET | ReClassNET/ReClass.NET | MIT | External app | Attribution |

## Release checklist

- [ ] Generate `THIRD-PARTY.md` from `research/repos-categorized.csv` plus this table.
- [ ] Run a license scan in CI (`cargo deny check licenses`, `pip-licenses`, `licensee`) and
      fail on AGPL/GPL in direct core dependencies.
- [ ] Manually verify every engine marked `NOASSERTION`.
- [ ] For sidecar engines: confirm there is no static linking — only binary/CLI invocation.
- [ ] For commercial engines: do not bundle SDKs/binaries; show a license requirement in the UI.
- [ ] Re-check licenses on every engine version bump.
- [ ] Keep the legal disclaimer in the README and UI.

## Rust dependencies (v0.5.0)

The Rust binary only uses permissive crates; there is no GPL/AGPL in its dependency graph.

| Crate | License | Used for |
|---|---|---|
| `goblin` | MIT | PE imports/exports, ELF, Mach-O parsing |
| `flate2` | MIT / Apache-2.0 | Inflating ZIP entries (APK AndroidManifest.xml) |
| `clap` | MIT / Apache-2.0 | CLI parsing |
| `serde`, `serde_json` | MIT / Apache-2.0 | IR/report serialization |
| `comfy-table` | MIT | Console tables |
| `regex` | MIT / Apache-2.0 | Heuristics (URLs/IPs/commands) |
| `sha1`, `sha2`, `md-5` | MIT / Apache-2.0 | Artifact hashes + evidence IDs |
| `toml`, `toml_edit` | MIT / Apache-2.0 | Engine manifests and SHA-256 pinning |
| `anyhow` | MIT / Apache-2.0 | Error context |
| `colored` | **MPL-2.0** | Console colors — weak, file-level copyleft; used unmodified as a dependency with notice |
| `hex` | MIT / Apache-2.0 | Hex encoding |
| `tempfile` (dev) | MIT / Apache-2.0 | Test fixtures |

| `x509-parser` | MIT / Apache-2.0 | APK signing certificates (v2/v3/v3.1 X.509 parsing) |

Recommendation: run `cargo deny check licenses` (or `cargo-license`) in CI before release.
If an absolutely permissive license set is required, replace `colored` with hand-written
ANSI escapes (not required today).

### YARA-X note

`yara-x = 1.23` was evaluated but **not used**:
- it requires `rustc >= 1.95` (current toolchain: 1.94.1);
- it pulls in `wasmtime` + `cranelift` (~100 crates), bloating the build and binary.

Replacement: the in-house signature engine `src/signatures.rs` (YARA subset, original code)
plus [`rules/avero-default.yar`](../rules/avero-default.yar). YARA-X can be added later as a
**sidecar** (not embedded) once the toolchain reaches 1.95.
