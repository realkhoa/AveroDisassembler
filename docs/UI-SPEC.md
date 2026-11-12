# AveroDisassembler — UI specification

| | |
|---|---|
| **Status** | Ready for implementation (spec v1.0) |
| **Audience** | UI agents implementing the Avero workbench |
| **Backend** | Rust CLI exists (v0.6.0). File mode and the local REST/SSE API (`avero serve`, `avero.api/v1`) are **implemented**; UI agents can build against either mode. |
| **Contracts** | `avero.report/v1` (report JSON), `avero.api/v1` (REST, see `docs/api/openapi.yaml`) |
| **Sample data** | `docs/api/sample-report.json` (real report generated from `tests/fixtures/sample.apk`) |
| **Language** | English UI. All user-visible strings must be English; structure the app for i18n but ship English first. |

This document is self-contained. A UI agent should be able to build the workbench without
reading the Rust source. The UI never performs analysis, never executes targets and never
talks to external engines directly.

---

## 0. TL;DR for UI agents

1. Build a **Next.js 15 (App Router) + React 19 + TypeScript (strict)** app in `apps/web`.
2. Ship **file mode first**: user opens/drops a `report.json` produced by
   `avero scan <file> --json`; everything renders from that JSON (sample provided).
3. Then add **API mode** behind the same data-source interface: run `avero serve` (local
   REST/SSE server at `http://127.0.0.1:8787`, implemented in v0.6.0). Mock it from
   `docs/api/sample-report.json` and `docs/api/openapi.yaml` if needed.
4. Implement the screens in section 6, in the milestone order of section 14 (M1 report
   viewer → M2 API mode → M3 decompile/manifest → M4 future diff).
5. Non-negotiable: **evidence-first UI** (every finding links to evidence), **read-only**
   (no patching), **local-only** (no telemetry, bind to loopback), **virtualized** lists,
   and **English-only** copy.
6. Definition of done: unit + Playwright tests, axe accessibility check, performance budget
   met (section 10), and all acceptance criteria in section 14 satisfied.

---

## 1. Product context

AveroDisassembler is an evidence-first reverse-engineering workbench. The Rust core probes a
file, runs analyzers, and produces a deterministic report (`avero.report/v1`) containing:

- **Triage**: hashes, entropy, kinds, architecture, compiler/toolchain hints.
- **Structure**: sections, imports, exports, metadata, strings.
- **Findings**: severity-ranked observations, each referencing **evidence**.
- **Coverage/unknowns/warnings**: what was analyzed, what failed, what remains unknown.

The UI's job is to make that report understandable and navigable: triage at a glance, drill
down from a finding to the exact bytes/metadata, and compare artifacts. It is a *report
workbench*, not an analysis engine.

### Design principles

1. **Evidence first** — a finding without a visible evidence trail is a bug.
2. **Read-only** — no editing, patching, renaming or writing to the analyzed artifact.
3. **Static-only** — clearly state that analysis is static and the target is not executed.
4. **Local-first** — files stay on the user's machine; no network calls except the local API.
5. **Fast** — virtualize everything, page large data, never block the main thread.
6. **Honest** — surface `coverage`, `unknowns` and `limitations` instead of hiding them.

## 2. Personas and primary workflows

| Persona | Goal | Main screens |
|---|---|---|
| **Game modder** | Understand a game update: what changed, which types/assets exist | Overview, .NET/IL2CPP, Diff (M4) |
| **.NET developer** | Inspect an assembly: types, methods, decompiled C# | Overview, .NET metadata, Decompile |
| **Malware/forensics analyst** | Triage an unknown file: what is it, what is suspicious, where is the evidence | Overview, Findings, Evidence, Strings, Signatures |
| **Mobile security engineer** | Inspect an APK: package, SDK, permissions, exported components, signing | Manifest, Findings, Evidence |

**Workflow A — triage a file (file mode)**
1. Open the app → drop `report.json` (or use API mode → scan a file).
2. Overview shows kind/arch/hashes, severity counts and top findings.
3. Click a finding → detail drawer → evidence chip → evidence inspector.
4. Use strings/hex to verify the context; copy hash/offset.

**Workflow B — audit evidence**
1. Findings list filtered by `severity=high`.
2. Open each finding; verify locator (`file_offset`/`rva`/`section`) in hex view.
3. Check `coverage` to see which analyzers ran and which were skipped.

**Workflow C — APK review**
1. Open APK report → Manifest screen.
2. Review package/version/SDK, dangerous permissions, exported components without permission,
   debuggable/allowBackup flags.
3. Pivot from a component/permission finding to its evidence.

**Workflow D — .NET decompile (API mode, M3)**
1. Open report → .NET metadata → pick a type → Decompile.
2. Core calls ILSpyCmd; UI shows progress; final C# appears in a read-only editor.
3. If the engine is not installed, show install instructions (`avero engine install ilspycmd`).

## 3. Scope

### In scope

- Report loading (file drag/drop, file picker, URL via API) and report metadata.
- Overview, findings, evidence, sections, imports/exports, strings, metadata, hex viewer.
- APK manifest view, .NET metadata view, signature matches, coverage/unknowns/warnings.
- Engine status view; decompile request and result view (API mode).
- Search/filter, keyboard navigation, deep links, export/copy helpers.
- Dark theme (default) and light theme; responsive from 1024 px upward (desktop-first).
- Accessibility and performance budgets from sections 9–10.

### Out of scope (do not implement here)

- Parsing/analysis logic (Rust core owns it).
- Disassembly/decompiler engines, x64dbg/Frida integration.
- Patching binaries, editing reports, renaming symbols in the analyzed file.
- Multi-user auth, cloud storage, remote telemetry, upload to third parties.
- Mobile phone layouts (a tablet layout at ≥768 px is acceptable, but desktop is primary).
- Diff UI beyond a placeholder until the API ships it (M4).

## 4. Architecture and integration

### 4.1 Recommended stack

| Area | Choice |
|---|---|
| Framework | Next.js 15 (App Router), React 19, TypeScript `strict` |
| Package manager | pnpm workspace (`apps/web`, root `pnpm-workspace.yaml`) |
| Styling | Tailwind CSS + CSS design tokens (section 8) |
| Server state | TanStack Query (caching, retries for API mode) |
| Local state | Zustand for UI-only state (selected tabs, drawer, filters in URL where shareable) |
| Tables/lists | TanStack Table + TanStack Virtual |
| Hex editor | Virtualized custom component (paged API or sliced ArrayBuffer in file mode) |
| Code view | Monaco Editor (read-only, C#/pseudo-C/assembly highlighting) |
| Graph (future) | React Flow (CFG/call graph, M4+) |
| Tests | Vitest + Testing Library, Playwright (E2E), axe-core (a11y) |

The app must run as `pnpm --filter web dev` on `http://localhost:3000` and build with
`next build` (static export is not required; local server is fine).

### 4.2 Two data modes behind one interface

The UI must not depend on how data arrives. Define one interface and two adapters:

```ts
export interface AveroDataSource {
  listReports?(): Promise<ReportSummary[]>;
  getReport(reportId: string): Promise<AveroReport>;
  getEvidence(reportId: string, evidenceId: string): Promise<Evidence>;
  getStrings(reportId: string, query: StringQuery): Promise<Page<StringEntry>>;
  getHex(reportId: string, offset: number, length: number): Promise<HexSlice>;
  getDisassembly?(reportId: string, start: number, count: number): Promise<Page<Instruction>>;
  decompile?(reportId: string, typeName?: string, engine?: string): Promise<Job>;
  getJob?(jobId: string): Promise<Job>;
  subscribeJob?(jobId: string, onEvent: (event: JobEvent) => void): () => void;
  getEngines?(): Promise<Engine[]>;
  getDiff?(oldReport: string, newReport: string): Promise<DiffResult>;
}
```

- **File mode (M1)**: `FileDataSource` parses an uploaded `report.json` (max 200 MB; parse in
  a Web Worker). No network. `getStrings` slices the in-memory array; `getHex` requires the
  original artifact bytes — if the user did not also provide the artifact, the Hex screen
  must show an explanatory empty state ("provide the original file to view bytes").
- **API mode (M2)**: `ApiDataSource` calls the local REST API. Base URL from settings
  (default `http://127.0.0.1:8787`). Never call from the server side; browser-only.
- Adapter selection in Settings; persist choice in `localStorage`.

### 4.3 Contract versioning

- Report schema id is `avero.report/v1`; API is `avero.api/v1`.
- If `schema_id` is unknown, show a non-blocking banner ("report schema X may not render
  correctly") and render known fields best-effort.
- The UI pins the contract version it implements in `apps/web/src/contracts/VERSION`.
- Do not rename JSON fields in the UI layer; use adapters if normalization is needed.

### 4.4 What the UI must never do

- Execute or load the analyzed binary.
- Send the artifact or report to any remote host.
- Render binary-derived strings as HTML (always text).
- Write to the artifact/report.
- Depend on `avero` CLI at runtime in API mode.

## 5. Information architecture

Top-level routes:

```
/                                  Home: open report / recent reports / API status
/report/[reportId]/overview        Triage dashboard (default route)
/report/[reportId]/findings        Findings table + detail drawer
/report/[reportId]/evidence        Evidence index (?id= opens one)
/report/[reportId]/sections        Sections + entropy
/report/[reportId]/imports         Imports and exports
/report/[reportId]/strings         Virtualized strings
/report/[reportId]/hex             Hex viewer (paged)
/report/[reportId]/disassembly     Disassembly (M4; placeholder before API)
/report/[reportId]/decompile       Decompile request/result (API mode, M3)
/report/[reportId]/manifest        APK AndroidManifest (when kind includes apk)
/report/[reportId]/dotnet          .NET metadata (when kind includes dotnet)
/report/[reportId]/signatures      Signature rule matches
/report/[reportId]/coverage        Coverage, unknowns, warnings
/report/[reportId]/metadata        Artifact metadata (key/value)
/report/[reportId]/diff            Diff (M4 placeholder)
/engines                           Engine packs + installation status
/settings                          Theme, API URL, adapter mode, data limits
```

Global layout:

```
┌─ Header: logo · report name/sha · mode badge (FILE/API) · global search · settings ─┐
├─ Sidebar (report sections, severity badges) ─┬─ Main content ──────────────────────┤
│ Overview                                     │  route content                    │
│ Findings (4)                                 │                                   │
│ Evidence                                     │                                   │
│ Sections / Imports / Strings / Hex           │                                   │
│ APK Manifest / .NET / Signatures             │                                   │
│ Coverage / Metadata                          │                                   │
├──────────────────────────────────────────────┴───────────────────────────────────┤
│ Status bar: schema version · analyzers ok · engine status · "static analysis"     │
└──────────────────────────────────────────────────────────────────────────────────┘
```

Sidebar items only appear when relevant to the report (`kinds`), e.g. APK Manifest only for
APKs; .NET only for `dotnet` artifacts. Unavailable items are hidden, not disabled.

## 6. Screen specifications

For every screen: **data** (fields from the report/API), **layout**, **interactions**,
**states**, **acceptance criteria**.

### 6.1 Home / open report

- **Purpose**: open a report, show recent reports, explain the tool.
- **Layout**: hero with app name + one-line description; drop zone (drag/drop or file
  picker); "Recent reports" list (localStorage, last 10: name, sha256 short, severity
  counts, opened time); API status card (file mode only vs connected).
- **States**: empty (first run), loading, parse error (show file name + error), unsupported
  schema warning.
- **Acceptance**: dropping a valid report opens Overview and persists it as recent; invalid
  JSON shows an error without crashing; no network requests in file mode.

### 6.2 Overview (triage dashboard)

- **Data**: artifact (`kinds`, `size`, `architecture`, `bits`, `endianness`, `entropy`,
  `hashes`, `path`), findings (counts by severity), facts (analyzer-specific, e.g.
  `pe.structure`, `apk.structure`), coverage, unknowns/warnings, evidence count.
- **Layout**:
  - Header row: file name, kind chips, copy button for SHA-256.
  - Cards: Size · Architecture · Entropy · Findings · Sections · Imports · Strings ·
    Evidence.
  - Severity bar: critical/high/medium/low/info counts, clickable → filtered Findings.
  - "Top findings" list (max 8, severity ordered) with confidence.
  - "Analyzers" mini-table (`coverage` with ok/ok cached), "Unknowns & warnings" panel.
  - APK: package/version/SDK/minSdk/debuggable chips; .NET: runtime/type/method counts.
- **Interactions**: click card → corresponding route; copy hash; open findings.
- **Acceptance**: matches report values exactly; severity counts equal findings; APK/extra
  cards only for matching kinds; unknowns/warnings visible without scrolling on 1080p.

### 6.3 Findings

- **Data**: findings (`id`, `severity`, `category`, `title`, `detail`, `confidence`,
  `evidence_ids`, `remediation`), linked evidence.
- **Layout**: filter bar (severity multi-select, category select, confidence min, text
  search); table columns Severity · Title · Category · Confidence; pagination or
  virtualization for >500 rows; right-side detail drawer with full detail, remediation and
  evidence chips.
- **Interactions**: row click opens drawer (deep link `?finding=<id>`); evidence chip opens
  Evidence inspector; copy finding text; filter state in URL query.
- **States**: no findings → empty state explaining coverage; filtered-empty state with
  "clear filters".
- **Acceptance**: severity filter+counter consistent; URL restores filters; evidence chip
  resolves to the correct evidence ID; keyboard `j/k` moves selection.

### 6.4 Evidence inspector

- **Data**: evidence (`id`, `producer {engine, version}`, `kind`, `locator`, `excerpt`,
  `confidence`, `limitations`), plus link back to referencing findings.
- **Layout**: list (searchable by ID/engine/kind) + detail panel. Locator rendered as a
  key/value table with friendly formatting (`rva: 0x...`, `file_offset: 0x...`,
  `section: .text`). Excerpt in monospace. "Used by findings" backlinks.
- **Interactions**: copy ID/locator; "view in hex" when locator has `file_offset` or `rva`
  (API/file mode with artifact bytes); deep link `?id=<evidenceId>`.
- **Acceptance**: every finding evidence ID resolves or shows "missing evidence" warning;
  producer engine+version shown; limitations shown when present.

### 6.5 Sections

- **Data**: `sections[]` (`name`, `va`, `vsize`, `raw_offset`, `raw_size`, `entropy`,
  `flags`).
- **Layout**: table with entropy bar (0–8 scale) and flags chips; sortable columns.
- **Interactions**: click row → Hex at `raw_offset`; copy offset/size.
- **Acceptance**: entropy bar clamps 0–8; rows >3 columns responsive; empty state for
  formats without sections.

### 6.6 Imports / exports

- **Data**: `imports[]` (`library`, `name`, `ordinal`, `iat_rva`), `exports[]` (`name`,
  `ordinal`, `rva`, `forwarder`).
- **Layout**: imports grouped by library (collapsible, count badge), search across
  library/function; exports table.
- **Acceptance**: library grouping correct; search filters both group and function names;
  ordinal-only imports render `ordinal N`.

### 6.7 Strings

- **Data**: `strings[]` (`offset`, `value`, `encoding`, `section`).
- **Layout**: virtualized list with columns Offset · Encoding · Section · Value; search
  (debounced 150 ms), encoding filter (ASCII/UTF-16LE), "copy all filtered" (max 10k).
- **Interactions**: click string → Hex at offset; copy value; run signature rule on string?
  (not in MVP).
- **Performance**: 100k+ rows must scroll at 60 fps via virtualization; no layout thrash.
- **Acceptance**: search highlights matches; offset column sortable; empty state when no
  strings.

### 6.8 Hex viewer

- **Data**: artifact bytes via `getHex(reportId, offset, length)` (API) or user-provided
  file (file mode); evidence locators for highlighting.
- **Layout**: toolbar (offset input, go, page up/down, byte search, highlight toggles);
  hex grid with address gutter, hex bytes, ASCII column; selected range info (offset, size,
  endianness-aware integer decode).
- **Interactions**: scroll requests pages in ≤64 KiB blocks; search (ASCII/hex patterns);
  jump from evidence/section/string; copy selection as hex/C array.
- **Limits**: no full-file loading in the browser for files >200 MB; show "provide file"
  state when bytes are unavailable.
- **Acceptance**: paging never blocks UI; offsets correct (decimal/0x accepted); highlight
  from evidence scrolls to and marks the range.

### 6.9 Metadata

- **Data**: `artifact.metadata` (key/value, values may be strings/numbers/booleans/arrays).
- **Layout**: searchable key/value table, JSON value expander, "copy JSON".
- **Acceptance**: nested values render safely as text; search by key and value.

### 6.10 APK manifest

- **Data**: `facts["apk.structure"]` (`apk_package`, `apk_version_code/name`, `apk_min_sdk`,
  `apk_target_sdk`, `apk_debuggable`, `apk_allow_backup`, `apk_permissions`,
  `apk_dangerous_permissions`, `apk_components[]`, `apk_exported_components`,\n  `apk_signature_schemes`, `apk_signers[]` (subject/issuer/validity/SHA-256/flags),\n  `apk_resources` (package, entry count, string resources)).
- **Layout**: summary cards; **risk banner** if `debuggable=true` (high) or exported
  components without permission; permissions table grouped dangerous/normal; components
  table (kind, name, exported, permission) with warning icon on risky rows.
- **Acceptance**: banners reflect facts exactly; dangerous permissions highlighted;
  component filter (exported only) works; evidence link for the manifest finding.

### 6.11 .NET metadata

- **Data**: `facts["dotnet.metadata"]` (`runtime_version`, `clr_runtime_version`,
  `module_name`, `type_count`, `method_count`, `field_count`, `assembly_ref_count`,
  `type_names_sample`, `obfuscation`).
- **Layout**: summary cards; obfuscation indicator (ratio + explanation); searchable type
  list (sample) with "Decompile" action (API mode only).
- **Acceptance**: counts and runtime shown; obfuscation heuristic explained with
  confidence; decompile action disabled with tooltip in file mode.

### 6.12 Decompile (M3, API mode)

- **Data**: job (`id`, `status`, `progress`, `error`), result (`files[]`, engine, type).
- **Layout**: assembly/type selector (from .NET metadata; free-text allowed), engine select
  (`ilspycmd` for .NET, `ghidra` for native; Ghidra requires JDK 25+), Run button; progress
  panel; result split view: file tree + Monaco read-only.
- **States**: engine missing → instructions `avero engine install ilspycmd`; job running
  (cancel), failed (stderr excerpt), success (files list + download/copy).
- **Acceptance**: decompile of a type returns C# in Monaco; progress updates without page
  reload; errors actionable; file mode shows "API mode required".

### 6.13 Disassembly (implemented API, M4 UI)

The API is live: `GET /api/reports/{id}/disassembly?start=<addr|entry0>&limit=<n>&analyze=true`.
Returns `items[]` with `address`, `bytes_hex`, `mnemonic`, `operands`, `size`, `kind`.

- **Layout**: toolbar (address input, go, prev/next page, analyze toggle); virtualized rows
  Address · Bytes · Mnemonic · Operands; current function/address label from the query.
- **Interactions**: jump to address, page through `limit` chunks (default 64, max 1000),
  copy address/bytes; clicking an address updates the URL (`?start=`).
- **States**: 409 `engine_missing` → instructions `avero engine install rizin`; 500 → error
  panel with retry; empty result → "no instructions at this address".
- **Acceptance**: requesting `start=0x1400019c0&limit=4` on a PE report renders the four
  instructions returned by the core; pagination uses the URL; no patching.

### 6.14 Coverage, unknowns, warnings

- **Data**: `coverage` (analyzer → `ok` | `ok (cached)`), `unknowns[]`, `warnings[]`.
- **Layout**: analyzer table with status chips; two lists with timestamps unavailable;
  copy all.
- **Acceptance**: every analyzer in the report appears; failed/skipped analyzers are
  visually distinct; unknown items are readable and copyable.

### 6.15 Signatures

- **Data**: `facts["signatures.rules"]` (`matched_rules`, `matches[]` with rule, matched
  patterns, first offset, severity).
- **Layout**: table of matched rules with severity chip; expand row → pattern stats and
  offset; link to the corresponding findings/evidence.
- **Acceptance**: no matches → positive empty state ("No signature rules matched"); rule
  metadata matches findings.

### 6.16 Engines

- **Data**: `engines[]` (`id`, `version`, `license`, `integration`, `installed`, `homepage`).
- **Layout**: table with install status; doctor panel (java/dotnet present); install button
  (API mode only) with confirmation; license column; external links open in new tab with
  `rel="noopener noreferrer"`.
- **Acceptance**: file mode explains engines are read-only/CLI-managed; installed state
  matches API; license shown for every engine.

### 6.17 Diff (API implemented, M4 UI)

- `POST /api/diffs` returns `avero.diff/v1`: artifact ids/sizes/kinds, findings
  added/removed/unchanged, sections/imports/exports/signature-rule changes, metadata changes
  and `size_delta`.
- **Layout**: two report pickers, summary (size delta, finding counts), tabs for Findings /
  Sections / Imports / Exports / Signatures / Metadata; changed rows highlighted; no patching.
- **States**: missing report → error panel with "scan both artifacts first"; identical
  reports → empty diff. Do not fabricate data when the API is unavailable.

### 6.18 Settings

- Theme (dark default / light), font size (12–16 px), API base URL (default
  `http://127.0.0.1:8787`), data adapter (file/api), clear cached reports, about/version
  (app + contract versions), disclaimer text.

## 7. Cross-cutting behaviour

- **Severity colors** (tokens in section 8): critical red, high orange, medium yellow, low
  green, info grey. Always pair color with a text label/icon (no color-only meaning).
- **Loading**: skeletons for cards/tables; spinners only for <2 s jobs; progress bars for
  jobs. No layout shift > 0.1 CLS.
- **Empty**: explain *why* (e.g. "No findings from the analyzers that ran"), link to
  Coverage.
- **Error**: inline error panel with human-readable message + "retry"; never a blank page.
  API errors include `code` and `message` from the contract.
- **Partial data**: if an optional section is missing, hide it and show in Coverage; never
  crash.
- **Deep links**: every screen state serializable in the URL (`?finding=`, `?id=`,
  `?severity=`, `?q=`, `?offset=`). Reload restores state.
- **Keyboard shortcuts**: `?` help overlay, `/` focus search, `j/k` next/prev row,
  `g o/f/e/s` go to overview/findings/evidence/sections, `c` copy focused value, `esc`
  close drawer/dialog. All shortcuts documented in the help overlay.
- **Copy actions**: copy hash, offset, string, evidence JSON; show toast confirmation.
- **No destructive actions**: reports and artifacts are read-only.

## 8. Design system

### 8.1 Tokens (dark theme, default; light theme mirrors with adjusted contrast)

| Token | Value | Usage |
|---|---|---|
| `--bg` | `#0e1116` | App background |
| `--panel` | `#161b22` | Cards, tables |
| `--panel-2` | `#1c2430` | Table headers, hover |
| `--border` | `#2b3440` | Borders |
| `--text` | `#d7dde5` | Primary text |
| `--muted` | `#8b96a5` | Secondary text |
| `--accent` | `#4cc2ff` | Links, active nav |
| `--accent-2` | `#7ee787` | Positive/secondary accent |
| `--critical` | `#ff5c6c` | Critical severity |
| `--high` | `#ff9f43` | High severity |
| `--medium` | `#ffd166` | Medium severity |
| `--low` | `#7ee787` | Low severity |
| `--info` | `#8b96a5` | Info severity |
| `--mono` | `Cascadia Mono, Consolas, monospace` | Hex, code, hashes |
| Radius | `10px` cards, `6px` inputs, `999px` chips | |
| Spacing scale | 4 / 8 / 12 / 16 / 24 / 32 px | |
| Typography | 14 px body/1.55, 12.5 px mono, 18–26 px headings | |

Contrast: text on panels ≥ 4.5:1 (AA); severity chips use tinted backgrounds with labels.

### 8.2 Component inventory

`AppShell` (header, sidebar, status bar) · `ReportHeader` · `KindChip` · `SeverityBadge` ·
`StatCard` · `SeverityBar` · `FindingsTable` + `FindingDrawer` · `EvidenceChip` ·
`EvidenceList` · `KeyValueTable` · `SectionTable` · `EntropyBar` · `ImportsTree` ·
`VirtualList` · `StringRow` · `HexViewer` · `ByteSearch` · `MonacoViewer` · `JobProgress` ·
`EmptyState` · `ErrorPanel` · `Banner` (info/warning/high risk) · `CopyButton` ·
`CommandPalette` (global search, `Ctrl/Cmd+K`) · `HelpOverlay` · `SettingsForm`.

All components must expose loading/empty/error states and be keyboard accessible.

## 9. Accessibility (WCAG 2.2 AA)

- Full keyboard navigation, visible focus ring (`2px` accent outline, never `outline: none`
  without replacement).
- Semantic headings and landmarks; every icon button has an accessible name.
- Tables use `<table>`/roles with headers; virtualized lists keep ARIA row counts
  (`aria-rowcount`, `aria-rowindex`).
- Color is never the only signal for severity (text/icon always present).
- Contrast ≥ 4.5:1 for text, ≥ 3:1 for large text/UI components.
- Respect `prefers-reduced-motion`; disable non-essential animation.
- Hex viewer: provide a text alternative (copy as text) and announce jumps (`aria-live`).
- Dialogs/drawers trap focus, close on `Esc`, restore focus on close.
- Test with axe (`@axe-core/playwright`) on every screen; zero serious/critical violations.

## 10. Performance budgets

| Metric | Budget |
|---|---|
| First contentful paint (localhost) | < 800 ms |
| Interactive route change | < 100 ms |
| Table/list scroll | 60 fps with 100k rows (virtualized) |
| Report parse (file mode, 50 MB) | < 2 s in a Web Worker, no UI block |
| Interaction p95 (filter/search) | < 100 ms (debounced input allowed) |
| Memory | no more than ~1.5× report size in file mode |
| Max supported report | 200 MB (warn above 50 MB; use streaming/chunked parse when feasible) |

Rules: code-split routes; lazy-load Monaco; do not render >200 DOM rows at once; debounce
search; memoize derived tables; avoid large JSON in React state (store normalized maps).

## 11. Security and privacy

- Bind API mode to `127.0.0.1` only; no auth for local use, but the server must reject
  non-loopback Host/Origin.
- No telemetry/analytics; no third-party scripts/fonts/CDNs (self-host fonts and icons).
- Content Security Policy: `default-src 'self'; img-src 'self' data:; style-src 'self'
  'unsafe-inline' (dev) / nonce in prod; connect-src 'self' http://127.0.0.1:8787;
  script-src 'self'`.
- All binary-derived text rendered via React text nodes; never `dangerouslySetInnerHTML`.
- External links open with `rel="noopener noreferrer"`; show the destination.
- File input only reads local files; never uploads anywhere in file mode.
- Clear disclaimer in the UI: "Static analysis only. The artifact is never executed."

## 12. API contract summary

Full spec: [`docs/api/openapi.yaml`](api/openapi.yaml). Example report:
[`docs/api/sample-report.json`](api/sample-report.json).

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | API/version status |
| POST | `/api/scans` | Upload artifact + options → `202 {job_id}` |
| GET | `/api/jobs/{jobId}` | Job status/progress/error |
| GET | `/api/jobs/{jobId}/events` | SSE progress stream |
| GET | `/api/reports/{reportId}` | Full report (`avero.report/v1`) |
| GET | `/api/reports/{reportId}/findings` | Paginated findings (`severity`, `category`, `q`, `cursor`, `limit`) |
| GET | `/api/reports/{reportId}/evidence/{evidenceId}` | Single evidence |
| GET | `/api/reports/{reportId}/sections` | Sections |
| GET | `/api/reports/{reportId}/imports` | Imports (grouped) |
| GET | `/api/reports/{reportId}/exports` | Exports |
| GET | `/api/reports/{reportId}/strings` | Paged strings (`offset`, `limit`, `q`, `encoding`) |
| GET | `/api/reports/{reportId}/hex` | Hex slice (`offset`, `length` ≤ 65536) |
| GET | `/api/reports/{reportId}/disassembly` | Paged instructions (M4) |
| POST | `/api/reports/{reportId}/decompile` | Type/assembly → `202 {job_id}` |
| GET | `/api/reports/{reportId}/apk-manifest` | Parsed manifest facts |
| GET | `/api/reports/{reportId}/dotnet` | .NET metadata facts |
| POST | `/api/diffs` | Diff two reports (M4) |
| GET | `/api/engines` | Engine packs + install status |
| POST | `/api/engines/{engineId}/install` | Install engine (M3+, explicit confirmation) |

Conventions:

- JSON only; errors `{"error":{"code":"...","message":"...","details":{}}}` with proper HTTP
  status (`400` bad request, `404` not found, `409` conflict, `422` validation, `500`).
- Pagination: `{items, next_cursor, total}`; opaque `cursor` strings.
- IDs are stable strings (`reportId` = artifact sha256; `evidenceId` from report). No
  filesystem paths from the API; artifact path is informational only.
- All endpoints are read-only except `POST /scans`, `POST /decompile`,
  `POST /engines/{id}/install` (each must require explicit UI confirmation).
- SSE event shape: `{type:"progress", job_id, stage, percent, message}`,
  `{type:"done", job_id, report_id}`, `{type:"error", job_id, error}`.

## 13. Testing strategy

| Layer | Tool | Requirements |
|---|---|---|
| Unit | Vitest | Data adapters (file/API), formatting helpers, filters, hex math, severity mapping |
| Component | Testing Library | Findings table/filters, evidence drawer, hex paging, manifest banners |
| E2E | Playwright | Open sample report → verify overview counts, findings → evidence → hex jump; APK manifest; keyboard shortcuts; settings |
| Mock API | Playwright route mocking or a tiny MSW handler | Same fixture; assert states for 404/500/stream errors |
| Accessibility | axe-core in Playwright | Zero serious/critical violations on all routes |
| Visual | Optional screenshots | Overview, Findings, Manifest, Hex (dark + light) |
| Fixtures | `docs/api/sample-report.json` (+ optional large generated report) | Golden values: 4 findings, package `com.avero.testsample`, permissions list |

Tests must not depend on the real `avero` binary; run against fixtures/mocks. A separate
smoke test may call the API if available but must skip gracefully.

## 14. Milestones and acceptance criteria

**M1 — Report viewer (file mode), 3–5 days**
- Open a report from disk; sidebar adapts to kinds; Overview matches report values.
- Findings → evidence inspector works; strings virtualized; sections/imports/metadata render.
- Hex viewer requires the original artifact: prompt for it and page correctly; evidence
  locators jump and highlight.
- Acceptance: E2E on `sample-report.json` passes all M1 criteria; axe clean; performance
  budget met for a 50 MB report.

**M2 — API mode, 2–3 days**
- Settings switch file/api; `/api/health` status badge; scan upload (optional) with job
  progress via SSE; all read endpoints paged.
- Acceptance: with mock API, same E2E flows pass; errors (404/500) show actionable panels;
  toggling modes preserves the current route.

**M3 — Manifest, .NET, decompile, engines, 3–4 days**
- APK manifest screen with risk banners and component table.
- .NET metadata screen + decompile flow with engine-missing guidance; Monaco read-only.
- Engines screen with install action behind confirmation.
- Acceptance: decompile result renders for a test assembly; engine install failure is
  surfaced; no writes to artifacts.

**M4 — Disassembly, diff, graphs (partially available)**
- Disassembly endpoint (`/disassembly`) is live (v0.8.0); build the M4 screen against it.
- Diff endpoint and CFG/call graph are future; keep those states clearly labelled.

## 15. Deliverables and handoff checklist

- [ ] `apps/web` app with routes from section 5 and components from section 8.
- [ ] `AveroDataSource` interface + `FileDataSource` + `ApiDataSource` + contract version pin.
- [ ] English copy only; i18n-ready string table.
- [ ] Tests: unit, component, Playwright E2E (file + mock API), axe.
- [ ] Performance verification notes (Lighthouse/Playwright traces) against section 10.
- [ ] Screenshots for Overview, Findings+Evidence, APK Manifest, Hex (dark + light).
- [ ] README in `apps/web` with setup/run/test instructions and contract versions.
- [ ] Optional CI job (`web-ci`) running lint/typecheck/test/build — coordinate with core
      team so the existing Rust workflow stays green.
- [ ] No changes to the Rust core, engine manifests, or report schema without a version bump
      and a note in `docs/IMPLEMENTATION-STATUS.md`.

## 16. Non-goals and future work

- No analysis, disassembly, decompilation or file parsing inside the browser beyond the
  contract fields.
- No binary patching, editing, or symbol renaming.
- No cloud sync, accounts, collaboration or telemetry.
- Future: light theme polish, drag-to-diff, saved views, plugin panels, MCP-linked chat with
  evidence gating.

## 17. Glossary

| Term | Meaning |
|---|---|
| **Report** | `avero.report/v1` JSON produced by the core; the UI's primary data source |
| **Artifact** | The analyzed file; UI only sees its metadata unless the user provides bytes |
| **Evidence** | Verifiable pointer (producer, locator, excerpt, confidence, limitations) |
| **Finding** | Severity-ranked observation referencing evidence IDs |
| **Coverage** | Which analyzers ran (`ok` / `ok (cached)`) |
| **File mode** | UI reads a local `report.json`; no server |
| **API mode** | UI talks to the local `avero serve` REST/SSE API |
