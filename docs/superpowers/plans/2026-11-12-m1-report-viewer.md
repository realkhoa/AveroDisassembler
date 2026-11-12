# AveroDisassembler M1 (Report Viewer File Mode) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the complete Milestone 1 (M1) web workbench for AveroDisassembler in `apps/web`, enabling users to inspect static reverse-engineering reports (`avero.report/v1`) in File Mode with evidence tracing, virtualized data tables, and dark theme design tokens.

**Architecture:** Monorepo using pnpm workspaces with Next.js 15 (App Router), React 19, TypeScript strict mode, and Tailwind CSS. The UI communicates with a decoupled `AveroDataSource` abstraction powered by `FileDataSource` in M1, keeping report state in memory/IndexedDB and URL search parameters as the source of truth for deep links.

**Tech Stack:** Next.js 15, React 19, TypeScript 5, Tailwind CSS, Lucide React icons, Vitest, Testing Library.

## Global Constraints

- **Language UI copy:** All user-visible strings and comments MUST be in English.
- **Contract version:** `avero.report/v1` pinned in `apps/web/src/contracts/VERSION`.
- **Static & Read-Only:** Analysis is strictly static; no binary patching or execution.
- **Evidence-First:** Every finding links to verifiable evidence with locator and excerpt.
- **Design Tokens:** Strict adherence to `docs/UI-SPEC.md` Section 8 tokens (`--bg: #0e1116`, `--panel: #161b22`, severity colors).
- **Quality & TSDoc:** 100% Doxygen / TSDoc coverage on all functions, classes, and exported interfaces.
- **Zero Untested Code:** Every module, adapter, helper, and component has corresponding unit tests passing in Vitest.

---

### Task 1: Monorepo Workspace & Next.js Scaffolding

**Files:**
- Create: `pnpm-workspace.yaml`
- Create: `package.json`
- Create: `apps/web/package.json`
- Create: `apps/web/tsconfig.json`
- Create: `apps/web/next.config.ts`
- Create: `apps/web/tailwind.config.ts`
- Create: `apps/web/postcss.config.mjs`
- Create: `apps/web/vitest.config.ts`
- Create: `apps/web/src/contracts/VERSION`

**Interfaces:**
- Produces: Runnable Next.js 15 project structure in `apps/web` with Vitest test runner.

- [x] **Step 1: Write root workspace configurations**
- [x] **Step 2: Write apps/web package.json, configs, and dependencies**
- [x] **Step 3: Run package installation via pnpm or npm**
- [x] **Step 4: Verify test runner executes with exit code 0**
- [x] **Step 5: Commit workspace scaffolding**

---

### Task 2: Core Report Types & Contract Validation

**Files:**
- Create: `apps/web/src/types/report.ts`
- Create: `apps/web/src/types/report.test.ts`

**Interfaces:**
- Produces: Type definitions for `AveroReport`, `Artifact`, `Finding`, `Evidence`, `Section`, `Import`, `Export`, `StringEntry`, `CoverageReport`.
- Consumes: `docs/api/sample-report.json` to validate JSON shape against types.

- [x] **Step 1: Write test validating sample-report.json against TypeScript contract**
- [x] **Step 2: Run test to observe failure/pass**
- [x] **Step 3: Implement complete report types in `apps/web/src/types/report.ts`**
- [x] **Step 4: Re-run test and verify contract validation passes**
- [x] **Step 5: Commit core types**

---

### Task 3: Data Source Abstraction & FileDataSource Implementation

**Files:**
- Create: `apps/web/src/lib/data-source/types.ts`
- Create: `apps/web/src/lib/data-source/file-data-source.ts`
- Create: `apps/web/src/lib/data-source/index.ts`
- Create: `apps/web/src/lib/data-source/file-data-source.test.ts`

**Interfaces:**
- Produces: `AveroDataSource` interface, `FileDataSource` class with `loadReport`, `getReport`, `getEvidence`, `getStrings`, `getHex`.
- Consumes: Report types from `apps/web/src/types/report.ts`.

- [x] **Step 1: Write unit tests for FileDataSource**
- [x] **Step 2: Run test to verify failure**
- [x] **Step 3: Implement `FileDataSource` and singleton factory**
- [x] **Step 4: Verify all unit tests pass**
- [x] **Step 5: Commit data source layer**

---

### Task 4: Design Tokens, Global CSS & AppShell Layout

**Files:**
- Create: `apps/web/src/app/globals.css`
- Create: `apps/web/src/components/layout/AppShell.tsx`
- Create: `apps/web/src/components/layout/Sidebar.tsx`
- Create: `apps/web/src/components/layout/Header.tsx`
- Create: `apps/web/src/components/layout/StatusBar.tsx`
- Create: `apps/web/src/app/layout.tsx`
- Create: `apps/web/src/components/layout/AppShell.test.tsx`

**Interfaces:**
- Produces: Reusable `AppShell` wrapping Header (with Mode Badge: FILE), Sidebar (adaptive to artifact kinds), and Status Bar.

- [x] **Step 1: Write unit tests for AppShell layout**
- [x] **Step 2: Implement Design Tokens in `globals.css` matching UI-SPEC Section 8**
- [x] **Step 3: Implement Header, Sidebar, StatusBar and AppShell components**
- [x] **Step 4: Verify AppShell tests pass**
- [x] **Step 5: Commit AppShell layout**

---

### Task 5: Home / Landing View & Drop Zone

**Files:**
- Create: `apps/web/src/components/home/DropZone.tsx`
- Create: `apps/web/src/components/home/RecentReportsList.tsx`
- Create: `apps/web/src/app/page.tsx`
- Create: `apps/web/src/components/home/DropZone.test.tsx`

**Interfaces:**
- Produces: Home page route `/` allowing users to drag/drop or browse for `report.json`, with sample report shortcut and recent reports listing.

- [x] **Step 1: Write unit tests for DropZone and file parsing**
- [x] **Step 2: Implement DropZone and RecentReportsList components**
- [x] **Step 3: Implement `apps/web/src/app/page.tsx`**
- [x] **Step 4: Verify tests pass**
- [x] **Step 5: Commit Home view**

---

### Task 6: Triage Overview Screen (`/report/[reportId]/overview`)

**Files:**
- Create: `apps/web/src/components/overview/StatCard.tsx`
- Create: `apps/web/src/components/overview/SeverityBar.tsx`
- Create: `apps/web/src/components/overview/TopFindingsList.tsx`
- Create: `apps/web/src/components/overview/AnalyzerTable.tsx`
- Create: `apps/web/src/app/report/[reportId]/overview/page.tsx`
- Create: `apps/web/src/components/overview/SeverityBar.test.ts`

**Interfaces:**
- Consumes: `AveroReport` data from `FileDataSource`.
- Produces: Dashboard with SHA-256 copy button, architecture/entropy/size cards, clickable severity bar, top 8 findings, analyzers summary, and APK/format chips.

- [x] **Step 1: Write unit tests for SeverityBar calculation and counts**
- [x] **Step 2: Implement StatCard, SeverityBar, TopFindingsList, AnalyzerTable**
- [x] **Step 3: Implement Overview page component**
- [x] **Step 4: Verify tests pass**
- [x] **Step 5: Commit Overview screen**

---

### Task 7: Findings Browser & Evidence Detail Drawer (`/report/[reportId]/findings`)

**Files:**
- Create: `apps/web/src/components/findings/SeverityBadge.tsx`
- Create: `apps/web/src/components/findings/EvidenceChip.tsx`
- Create: `apps/web/src/components/findings/FindingDrawer.tsx`
- Create: `apps/web/src/components/findings/FindingsTable.tsx`
- Create: `apps/web/src/app/report/[reportId]/findings/page.tsx`
- Create: `apps/web/src/components/findings/FindingsFilter.test.ts`

**Interfaces:**
- Consumes: Findings and linked Evidence from `AveroReport`.
- Produces: Filterable table with severity multi-select, category filter, text search, right-side detail drawer with remediation and clickable evidence chips.

- [x] **Step 1: Write unit tests for filtering findings by severity and query**
- [x] **Step 2: Implement SeverityBadge, EvidenceChip, FindingDrawer, FindingsTable**
- [x] **Step 3: Implement Findings page component with URL query synchronization**
- [x] **Step 4: Verify unit tests pass**
- [x] **Step 5: Commit Findings screen**

---

### Task 8: Evidence Inspector Screen (`/report/[reportId]/evidence`)

**Files:**
- Create: `apps/web/src/components/evidence/LocatorTable.tsx`
- Create: `apps/web/src/components/evidence/EvidenceInspector.tsx`
- Create: `apps/web/src/app/report/[reportId]/evidence/page.tsx`
- Create: `apps/web/src/components/evidence/LocatorTable.test.ts`

**Interfaces:**
- Consumes: Evidence items and finding backlinks.
- Produces: Searchable evidence list, producer engine/version, structured locator table (`file_offset`, `rva`, `section`), monospace excerpt, backlink findings, and "View in Hex" navigation button.

- [x] **Step 1: Write unit tests for locator formatting and RVA hex conversions**
- [x] **Step 2: Implement LocatorTable and EvidenceInspector components**
- [x] **Step 3: Implement Evidence page component supporting `?id=<evidenceId>` deep link**
- [x] **Step 4: Verify tests pass**
- [x] **Step 5: Commit Evidence screen**

---

### Task 9: Sections, Entropy & Imports/Exports Screens

**Files:**
- Create: `apps/web/src/components/sections/EntropyBar.tsx`
- Create: `apps/web/src/app/report/[reportId]/sections/page.tsx`
- Create: `apps/web/src/app/report/[reportId]/imports/page.tsx`
- Create: `apps/web/src/components/sections/EntropyBar.test.ts`

**Interfaces:**
- Consumes: `sections[]`, `imports[]`, `exports[]` from `AveroReport`.
- Produces:
  - Sections table with 0-8 entropy meter and flags chips, jump to hex.
  - Imports grouped by library with count badges and function search, plus exports table.

- [x] **Step 1: Write unit tests for EntropyBar clamping and color thresholding**
- [x] **Step 2: Implement EntropyBar and Sections table**
- [x] **Step 3: Implement Imports grouped tree view and Exports table**
- [x] **Step 4: Verify tests pass**
- [x] **Step 5: Commit Sections and Imports screens**

---

### Task 10: Virtualized Strings & Hex Viewer Screens

**Files:**
- Create: `apps/web/src/components/strings/StringsViewer.tsx`
- Create: `apps/web/src/app/report/[reportId]/strings/page.tsx`
- Create: `apps/web/src/components/hex/HexViewer.tsx`
- Create: `apps/web/src/app/report/[reportId]/hex/page.tsx`
- Create: `apps/web/src/components/hex/HexViewer.test.ts`

**Interfaces:**
- Consumes: `strings[]` and raw binary bytes or artifact slice.
- Produces:
  - Virtualized strings list with debounced search and ASCII/UTF-16 filter.
  - Paged Hex Viewer with 16 bytes/row, address gutter, ASCII representation, offset jump input, and empty state when raw binary is not provided.

- [x] **Step 1: Write unit tests for Hex byte formatting and offset navigation**
- [x] **Step 2: Implement StringsViewer component with virtualized list**
- [x] **Step 3: Implement HexViewer component**
- [x] **Step 4: Verify tests pass**
- [x] **Step 5: Commit Strings and Hex screens**

---

### Task 11: Metadata, Coverage & Settings Screens

**Files:**
- Create: `apps/web/src/app/report/[reportId]/metadata/page.tsx`
- Create: `apps/web/src/app/report/[reportId]/coverage/page.tsx`
- Create: `apps/web/src/app/settings/page.tsx`

**Interfaces:**
- Consumes: `artifact.metadata`, `coverage`, `unknowns[]`, `warnings[]`.
- Produces:
  - Searchable key/value metadata explorer with copy JSON action.
  - Analyzers coverage table with ok/cached badges and unknowns/warnings list.
  - Settings page with theme toggle, API URL input, mode switch, cache clear, and version info.

- [x] **Step 1: Implement Metadata page with recursive JSON tree expander**
- [x] **Step 2: Implement Coverage & Unknowns page**
- [x] **Step 3: Implement Settings page**
- [x] **Step 4: Verify pages compile and render**
- [x] **Step 5: Commit Metadata, Coverage and Settings**

---

### Task 12: End-to-End Build, Test Verification & Static Code Review

**Files:**
- Test all components with `pnpm --filter web test` (or `bun test`).
- Build production bundle with `pnpm --filter web build`.
- Verify with `docs/api/sample-report.json`.

- [x] **Step 1: Execute full unit test suite**
- [x] **Step 2: Run production Next.js build and verify exit code 0**
- [x] **Step 3: Run static code review and resolve any issues**
- [x] **Step 4: Commit and finalize**
