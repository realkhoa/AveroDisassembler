# Signature engine (native Rust, YARA subset)

Avero scans signatures with a **native Rust engine embedded in the binary**. No Python, no
YARA installation, no network downloads. Rules are compiled into the executable at build
time and compiled lazily into an in-memory ruleset once per process.

## Why not YARA-X?

- `yara-x` 1.23 requires **rustc ≥ 1.95** (this project builds on 1.94.1) and pulls in
  **wasmtime + cranelift** (~100 crates), which makes the binary much larger and builds
  much slower — the opposite of the "fast, small binary" goal.
- YARA-X remains a good option as an optional **sidecar** once the toolchain is ≥ 1.95.
  The native engine covers the default ruleset and keeps the binary at ~3.4 MB.

## Supported syntax

```text
rule rule_name
{
    meta:
        description = "Short description"
        severity = "info" | "low" | "medium" | "high" | "critical"
        category = "packing"
    strings:
        $a = "ASCII text" [ascii] [wide] [nocase]
        $b = { 48 8B ?? 00 }
    condition:
        any of them          // or: all of them / N of them / $a
}
```

| Feature | Support |
|---|---|
| Text patterns | ASCII, `wide` (UTF-16LE), `nocase` |
| Hex patterns | bytes + `??` wildcard (no nibble wildcards, jumps or alternatives) |
| Meta | `description`, `severity`, `category` |
| Conditions | `any of them`, `all of them`, `N of them`, `$id` |
| Comments | `//` and `/* ... */` |
| Not supported | modules (pe/elf/…), regex, advanced `for`/`of` expressions, includes, rule dependencies |

The default ruleset lives in [`rules/avero-default.yar`](../rules/avero-default.yar) and is
embedded with `include_str!` in `src/signatures.rs`.

## Default ruleset

| Rule | Severity | Category | Meaning |
|---|---|---|---|
| `upx_packer` | high | packing | UPX markers (UPX0/UPX1/UPX!) |
| `packer_section_names` | high | packing | Section names of common packers/protectors |
| `anti_debug_api_strings` | medium | anti-analysis | Anti-debug API names |
| `suspicious_shell_commands` | high | execution | PowerShell -enc, cmd /c, bitsadmin, mshta… |
| `persistence_autostart` | medium | persistence | Run/RunOnce/Winlogon/schtasks |
| `credential_access_strings` | medium | credential-access | sekurlsa/lsass/SAM |
| `base64_encoded_pe` | high | encoding | Base64-encoded PE header |
| `aes_sbox_constant` | info | crypto | AES S-box constant |
| `net_obfuscator_markers` | low | obfuscation | ConfuserEx/Dotfuscator/… |
| `virtualization_detection` | low | anti-analysis | VMware/VirtualBox/QEMU/Sandboxie |
| `wallet_crypto_strings` | low | data | wallet.dat/bitcoin/mnemonic |
| `rmm_tool_strings` | low | remote-access | TeamViewer/AnyDesk/mstsc/VNC/ngrok |

Each match produces a `Signature: <rule>` finding with evidence containing the rule ID,
number of matched patterns, first match offset, confidence 0.7 and the limitation
"verify context".

## Adding a rule

1. Edit `rules/avero-default.yar` (or add a file and `include_str!` it).
2. `scripts\build.bat build --release` — rules are compiled into the binary.
3. `scripts\build.bat test` — the `default_rules_compile` test catches syntax errors.
4. Convention: require at least two patterns for rules with false-positive risk; choose
   severity/category that reflect confidence.

## Performance

- The default ruleset (~40 patterns) adds roughly 10 ms when scanning a 352 KB PE.
- The ruleset is compiled once per process (lazy `OnceLock`); analysis results are cached
  under `.avero/cache` keyed by artifact hash.

## Roadmap

- Add `--rules <file.yar>` to load external rulesets (currently embedded only).
- Support hex jumps `[n-m]`, nibble wildcards and `#pattern > N` conditions.
- Once the toolchain is ≥ 1.95, add YARA-X as an optional **sidecar** (not embedded) for
  full YARA ruleset compatibility.
