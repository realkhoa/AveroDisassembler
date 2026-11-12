# AveroDisassembler Web Workbench — M1 Design Document

- **Date:** 2026-11-12
- **Topic:** Milestone 1 (M1) — Report Viewer (File Mode)
- **Status:** Approved (Direct implementation per user instruction)
- **Reference Specification:** [`docs/UI-SPEC.md`](file:///e:/sourcecode/AveroDisassembler/docs/UI-SPEC.md)
- **Contract Schema:** `avero.report/v1`
- **Sample Data Fixture:** [`docs/api/sample-report.json`](file:///e:/sourcecode/AveroDisassembler/docs/api/sample-report.json)

---

## 1. Overview & Goals

AveroDisassembler is an evidence-first, read-only, static-only reverse-engineering workbench. The Rust core (`avero`) produces deterministic JSON reports conformant to schema `avero.report/v1`.

The goal of Milestone 1 (M1) is to build the web-based report viewer in `apps/web`:
- Operates entirely in **File Mode** without requiring a live server or network access.
- Allows users to open or drag-and-drop any valid `report.json` (tested against `sample-report.json`).
- Stores opened reports locally in IndexedDB / localStorage for quick resumption in "Recent Reports".
- Renders all core triage and structural screens specified in `docs/UI-SPEC.md` Section 6.
- Enforces strict evidence linking: every finding links to its evidence items with locator and excerpt inspection.

---

## 2. Architecture & Tech Stack

### 2.1 Workspace Structure
- Monorepo root configuration: `pnpm-workspace.yaml` with `packages: ['apps/*']`.
- Frontend application location: `apps/web/`.
- Runtime & Bundler: Next.js 15 (App Router), React 19, TypeScript in `strict` mode.
- Styling: Tailwind CSS configured with custom CSS design tokens matching Section 8 of `UI-SPEC.md`.
- State Management:
  - Zustand for client-side transient state (active report, open drawer, user preferences).
  - URL Query Parameters as single source of truth for view states (`?finding=`, `?id=`, `?severity=`, `?q=`, `?offset=`).
- Virtualization: `@tanstack/react-virtual` for high-volume tabular and list views (strings table, hex bytes).

### 2.2 Data Layer Architecture (`AveroDataSource`)
A clean abstraction decouples the UI from the data acquisition method:
```ts
export interface AveroDataSource {
  listReports?(): Promise<ReportSummary[]>;
  getReport(reportId: string): Promise<AveroReport>;
  getEvidence(reportId: string, evidenceId: string): Promise<Evidence>;
  getStrings(reportId: string, query: StringQuery): Promise<Page<StringEntry>>;
  getHex(reportId: string, offset: number, length: number): Promise<HexSlice>;
  getMetadata(reportId: string): Promise<Record<string, unknown>>;
  getCoverage(reportId: string): Promise<CoverageReport>;
}
```
- In **M1 (File Mode)**, `FileDataSource` is the active adapter. It stores parsed reports in memory and caches summaries in `localStorage`/`IndexedDB`.
- If an artifact binary is not supplied alongside `report.json`, the Hex Viewer gracefully renders an informative empty state explaining that the original artifact is required to inspect raw bytes.

---

## 3. Information Architecture & Routing

All routes are nested under the Next.js App Router in `apps/web/src/app/`:

| Route | View Name | Description |
|---|---|---|
| `/` | Home / Landing | Drop zone for `report.json`, file picker, recent reports list, mode indicator badge |
| `/report/[reportId]/overview` | Triage Overview | High-level artifact triage, SHA-256 copy, hashes, entropy card, severity distribution bar, top findings list, analyzer coverage summary |
| `/report/[reportId]/findings` | Findings Browser | Filterable/searchable findings table with severity filters, confidence score, right-side detail drawer with remediation and clickable evidence chips |
| `/report/[reportId]/evidence` | Evidence Inspector | List of evidence items by ID, producer engine & version, locator details (`rva`, `file_offset`, `section`), monospace excerpt, backlinks to findings |
| `/report/[reportId]/sections` | Sections & Entropy | Table of binary sections, sizes, permissions/flags, and visual 0–8 entropy meters |
| `/report/[reportId]/imports` | Imports & Exports | Collapsible tree of imported functions grouped by library with counts, plus exports table |
| `/report/[reportId]/strings` | Strings Viewer | Virtualized table of strings with debounced full-text search and encoding filter (ASCII / UTF-16LE) |
| `/report/[reportId]/hex` | Hex Viewer | Virtualized 16-bytes-per-row hex grid with address gutter, hex representation, ASCII column, offset jump input, and evidence locator highlight |
| `/report/[reportId]/metadata` | Metadata Explorer | Searchable key/value table for artifact properties with nested JSON viewer |
| `/report/[reportId]/coverage` | Coverage & Unknowns | Analyzer status table (`ok` / `ok (cached)` / `failed`), warnings list, and unknowns list |
| `/settings` | Settings & Info | Theme toggle, API base URL configuration (for upcoming M2), active data adapter, cache management, version disclaimer |

---

## 4. Visual Tokens & Accessibility

### 4.1 Design Tokens (Dark Theme Default)
- Background: `--bg: #0e1116`
- Panels/Cards: `--panel: #161b22`, `--panel-2: #1c2430`
- Border: `--border: #2b3440`
- Text: `--text: #d7dde5`, `--muted: #8b96a5`
- Primary Accent: `--accent: #4cc2ff`, Secondary Accent: `--accent-2: #7ee787`
- Severities:
  - Critical: `--critical: #ff5c6c`
  - High: `--high: #ff9f43`
  - Medium: `--medium: #ffd166`
  - Low: `--low: #7ee787`
  - Info: `--info: #8b96a5`
- Monospace font: `Cascadia Mono, Consolas, ui-monospace, monospace`

### 4.2 Accessibility (WCAG 2.2 AA)
- Contrast ratio ≥ 4.5:1 on all text labels.
- Dual-indicator severity signals (severity badge pairs color with clear text label and severity icon, never color alone).
- Full keyboard support: `Esc` closes drawers/modals, tab navigation with visible focus rings.

---

## 5. Testing & Verification Plan

1. **Unit Tests (Vitest)**:
   - Data source contract compliance and parser (`FileDataSource`).
   - Entropy formatting and scale clamping (0–8).
   - Findings filtering (severity multi-select, category, search text, confidence thresholds).
   - Hex address formatting and slice math.
2. **End-to-End Fixture Validation**:
   - Verify loading `docs/api/sample-report.json`.
   - Verify all 4 findings, linked evidence, APK structure facts, hashes (`com.avero.testsample`).
3. **Build Pass Gate**:
   - `pnpm --filter web build` compiles cleanly with exit code 0.
   - Vitest suite passes 100%.
