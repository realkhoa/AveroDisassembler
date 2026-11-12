# Engine packs & installer

Avero delegates heavy lifting (native decompilation, .NET decompilation, DEX, …) to
external open-source engines using a **sidecar process** model: no GPL/AGPL code is linked
into the binary, and no Python is required.

Engines are described by TOML manifests in [`engines/`](../engines). The Avero binary only
contains the manifest reader plus install/verify logic; engine payloads are never committed
to the repository.

## Commands

```powershell
avero engine list                 # engine table + install status
avero engine doctor               # Java/.NET/engine prerequisite checks
avero engine install ilspycmd     # dotnet tool (requires .NET SDK + network)
avero engine install rizin@0.9.1  # download zip, verify SHA-256, extract
avero engine pin rizin            # download archive, compute SHA-256, write to manifest
avero engine install rizin --from .\rizin.zip   # offline / pre-downloaded archive
avero engine install ghidra --allow-unpinned    # only for archives you verified yourself
avero engine install rizin --force              # reinstall
```

Non-zero exit codes are accompanied by actionable error messages.

## Manifest

```toml
id = "rizin"
version = "0.9.1"
license = "LGPL-3.0"
integration = "sidecar"            # sidecar | in-process | external-app
binaries = ["rizin"]               # executable basenames to locate after install
install_dir = "engines/rizin/0.9.1"

[install]
method = "zip"                     # zip (default) | dotnet-tool

[download.windows-x64]
url = "https://…/rizin-windows-shared64-v0.9.1.zip"
sha256 = "<pinned>"                # required unless --allow-unpinned / --from
archive = "zip"

[healthcheck]
command = ["rizin", "-v"]
timeout_s = 30
```

For `dotnet-tool`:

```toml
[install]
method = "dotnet-tool"
package = "ilspycmd"
version = "11.2.0.10050"
```

## Safety principles

- **No downloads during scans.** Only `engine install` fetches anything; scans use engines
  that are already installed.
- **SHA-256 verification** (streaming) before extraction. Unpinned hashes are rejected
  unless `--allow-unpinned` or `--from` is used.
- **No shell strings**: every command uses an argument array (`curl`, `tar`, `dotnet tool`).
- **No engine payloads in git**: `.gitignore` tracks only `engines/*.toml` and ignores
  `engines/.cache`, `engines/.tmp` and install directories.
- Engines install into `engines/<id>/<version>`; `avero engine list` reports status.

## Offline / air-gapped

```powershell
# On a networked machine
avero engine pin rizin
Copy-Item engines\.cache\rizin-0.9.1-windows-x64.zip D:\bundle\
Copy-Item engines\rizin.toml D:\bundle\

# On the offline machine
avero engine install rizin --from D:\bundle\rizin-0.9.1-windows-x64.zip
```

## Available engines

| ID | Method | License | Used for |
|---|---|---|---|
| `ilspycmd` | dotnet-tool | MIT | `avero dotnet decompile` |
| `rizin` | zip | LGPL-3.0 | `avero disasm` + API `/disassembly` |
| `ghidra` | zip | Apache-2.0 | native decompilation via `avero decompile` (JDK 25+ required) |
| `jadx` | zip | Apache-2.0 | APK/DEX decompilation (adapter P3) |

Full license/integration matrix: [THIRD-PARTY-ENGINES.md](THIRD-PARTY-ENGINES.md).

## .NET decompilation via ILSpyCmd

```powershell
avero engine install ilspycmd
avero dotnet decompile SampleLib.dll --type SampleLib.Class1 --out .\decompiled
avero dotnet decompile SampleLib.dll --json
```

The engine is resolved in this order: `engines/ilspycmd/<version>` → `PATH`. Real
executables, `.cmd`/`.bat` shims (Windows) and `dotnet tool` apphosts are supported.

## Native decompilation via Ghidra

Ghidra 12.2 is installed as a sidecar pack and requires **JDK 25+** (Ghidra's launcher
checks the Java version; set `JAVA_HOME` or put JDK 25 on `PATH`).

```powershell
avero engine pin ghidra                 # download + SHA-256 pin the release archive (~570 MB)
avero engine install ghidra             # verify, extract, locate support/analyzeHeadless.bat
avero decompile notepad.exe --limit 20 --out .\native-decompiled
avero decompile notepad.exe --function entry --limit 1 --json
```

How it works:

1. Avero writes an embedded GhidraScript (`AveroExport.java`) to a temporary script directory.
2. It runs `support/analyzeHeadless <tmp>/project AveroProject -import <file> -scriptPath ...
   -postScript AveroExport.java <out.json> [only] [limit] -deleteProject`.
3. The script decompiles functions (limit/timeout bounded) and writes JSON with
   `name`, `entry`, `size`, `decompiled`.
4. Avero writes one `<function>.c` per function plus `decompile.json`, or prints JSON with
   `--json`.

The same engine is available through the API:
`POST /api/reports/{id}/decompile` with `{"engine":"ghidra","type":"entry","limit":2}`.

Caveats: headless analysis of large binaries is CPU-heavy (minutes); the default CLI limit
is 300 functions and the default timeout is 900 s. Ghidra output is derived code, not the
original source; treat it as an aid, not ground truth.

## Native disassembly via rizin

rizin 0.9.1 is installed as a sidecar (LGPL-3.0) and driven in JSON mode:

```powershell
avero engine pin rizin
avero engine install rizin
avero disasm notepad.exe --count 16
avero disasm notepad.exe --address 0x1400019c0 --count 8 --json
avero disasm notepad.exe --analyze --count 32       # runs `aa` first (slower)
```

How it works:

1. Avero runs `rizin -q -c "e scr.color=0" [-c "aa"] -c "s <addr|entry0>" -c "pdj <n>" <file>`.
2. `pdj` emits JSON instructions: `offset`, `bytes`, `disasm`, `size`, `type`.
3. Avero splits mnemonic/operands, bounds the count (1–1000) and returns/prints a table.

The same adapter backs `GET /api/reports/{id}/disassembly?start=0x...&limit=N&analyze=true`.
Without `--analyze`/`analyze=true`, rizin still resolves `entry0` from the file header, so
entry/address seeks are fast; function-name seeks need analysis.
