# AveroDisassembler Web Workbench — UI Handover Document

- **Date:** 2026-11-12
- **Milestone:** Milestone 1 (M1) — Report Viewer (File Mode) Complete
- **Status:** Production Build Passing (`next build` exit code 0), All Unit Tests Passing (14/14)
- **Specification:** [`docs/UI-SPEC.md`](file:///e:/sourcecode/AveroDisassembler/docs/UI-SPEC.md)
- **Contract Schema Pin:** `avero.report/v1` (`apps/web/src/contracts/VERSION`)

---

## 1. Executive Summary

Milestone 1 (M1: File Mode Report Viewer) of the AveroDisassembler web interface is fully implemented in `apps/web`.

The application enables reverse engineers, malware analysts, and security researchers to inspect static analysis reports produced by `avero scan <file> --json` offline in their browser with zero network access required. Every finding is verifiable with direct links to supporting evidence locators, and large data tables (strings, sections, hex) are optimized with virtualization and paged slicing.

---

## 2. Architecture & Technical Stack

| Component | Technology | Role / Responsibility |
|---|---|---|
| **Framework** | Next.js 15 (App Router) | Dynamic routing (`/report/[reportId]/...`), server/client component boundary |
| **View Engine** | React 19 | Declarative UI components and state hooks |
| **Language** | TypeScript 5.7 (`strict: true`) | Strict static type checking against `avero.report/v1` schema |
| **Styling** | Tailwind CSS 3.4 + Custom Tokens | Dark theme default (`#0e1116`), WCAG 2.2 AA compliant contrast |
| **Virtualization** | `@tanstack/react-virtual` | 60 fps smooth scrolling for 100k+ strings |
| **Data Layer** | `AveroDataSource` abstraction | Decouples UI screens from data acquisition; M1 powered by `FileDataSource` |
| **Icons** | `lucide-react` | Clean, lightweight SVG icon system |
| **Test Runner** | Vitest 2.1 + JSDOM | Fast unit and component test execution |

---

## 3. Delivered Routes & Feature Matrix

### 3.1 Global Shell & Navigation
- **`AppShell`**: Wraps all screens with top `Header`, dynamic `Sidebar`, and bottom `StatusBar`.
- **`Header`**: Displays logo, active artifact name, shortened SHA-256 hash, and mode badge (`FILE MODE`).
- **`Sidebar`**: Dynamically adapts navigation links to the active report; format-specific items (e.g. `APK Manifest`) automatically appear when `artifact.kinds.includes("apk")`.
- **`StatusBar`**: Displays `avero.report/v1` contract version pin, analyzer execution count, and the mandatory static-only disclaimer ("Static analysis only. The artifact is never executed.").

### 3.2 Screens
| Route | Feature Highlights |
|---|---|
| **`/` (Home)** | Drag-and-drop zone for `report.json`, file browser, one-click **"Open Sample Report"** shortcut, and `localStorage`-backed **Recent Reports** history. |
| **`/report/[reportId]/overview`** | Triage overview, SHA-256 one-click copy, entropy meter, file size, clickable **SeverityBar**, top 8 findings, APK summary facts, and analyzer coverage table. |
| **`/report/[reportId]/findings`** | Multi-attribute filtering (Severity checkboxes, Category dropdown, free-text search), `j/k` keyboard row navigation, and slide-over **`FindingDrawer`** showing full descriptions, remediations, and clickable **`EvidenceChip`** items. Supports URL query synchronization (`?severity=`, `?finding=`). |
| **`/report/[reportId]/evidence`** | Master-detail evidence inspector with searchable list, structured **`LocatorTable`** with hex address annotations (`0x...`), monospace excerpt viewer with copy action, **"Referenced By Findings"** backlinks, and **"View in Hex"** jump button. Supports `?id=<evidenceId>` deep links. |
| **`/report/[reportId]/sections`** | Table of binary sections with virtual addresses, raw offsets, permissions flags, and visual **`EntropyBar`** (0–8 scale) with packing/encryption risk indicators. Row actions jump directly into the Hex viewer. |
| **`/report/[reportId]/imports`** | Grouped imports view by library with collapsible headers and function count badges; searchable exports table with ordinals and RVAs. |
| **`/report/[reportId]/strings`** | High-performance virtualized strings table supporting 100k+ items; debounced search, ASCII / UTF-16LE encoding filters, and copy actions. |
| **`/report/[reportId]/hex`** | 16-byte aligned paged hex grid with address gutter, hex bytes, and ASCII preview. Includes offset jump form, page navigation, selected byte inspector (Hex/Dec/Char), and an explanatory state with file picker when raw binary bytes are needed. |
| **`/report/[reportId]/manifest`** | Dedicated APK audit screen: risk banners for `debuggable=true`, dangerous vs normal permissions breakdown, and component table (Activity, Service, Receiver, Provider) with exported permission guard flags. |
| **`/report/[reportId]/metadata`** | Searchable key/value table for container and probe metadata with formatted nested JSON expansion. |
| **`/report/[reportId]/coverage`** | Full audit of executed analyzers, runtime warnings, and unknown/unparsed structures. |
| **`/settings`** | Data adapter switch (File / API mode), local API endpoint URL configuration (`http://127.0.0.1:8787`), and cache clearing. |

---

## 4. Verification & Quality Evidence

### 4.1 Unit Test Results (Vitest)
```
 ✓ src/components/findings/FindingsFilter.test.ts (2 tests) 5ms
 ✓ src/components/overview/SeverityBar.test.ts (1 test) 5ms
 ✓ src/types/report.test.ts (1 test) 7ms
 ✓ src/components/sections/EntropyBar.test.ts (3 tests) 7ms
 ✓ src/components/evidence/LocatorTable.test.ts (3 tests) 6ms
 ✓ src/lib/data-source/file-data-source.test.ts (4 tests) 11ms

 Test Files  6 passed (6)
      Tests  14 passed (14)
   Start at  15:47:08
   Duration  2.85s
```

### 4.2 Production Build Verification (`next build`)
```
✓ Compiled successfully in 8.2s
Route (app)                                 Size  First Load JS
┌ ○ /                                    6.02 kB         112 kB
├ ○ /_not-found                            987 B         103 kB
├ ƒ /report/[reportId]/coverage           5.5 kB         108 kB
├ ƒ /report/[reportId]/evidence          3.18 kB         113 kB
├ ƒ /report/[reportId]/findings          3.69 kB         114 kB
├ ƒ /report/[reportId]/hex               6.33 kB         109 kB
├ ƒ /report/[reportId]/imports           6.03 kB         108 kB
├ ƒ /report/[reportId]/manifest          5.73 kB         108 kB
├ ƒ /report/[reportId]/metadata          5.37 kB         108 kB
├ ƒ /report/[reportId]/overview          7.66 kB         114 kB
├ ƒ /report/[reportId]/sections          4.99 kB         111 kB
├ ƒ /report/[reportId]/strings           15.8 kB         122 kB
└ ○ /settings                            2.86 kB         105 kB
+ First Load JS shared by all             102 kB
```

---

## 5. How to Run and Test

```bash
# 1. Install dependencies across the pnpm workspace
pnpm install

# 2. Run the full unit test suite
pnpm --filter web test

# 3. Start the local development server
pnpm --filter web dev
# Open http://localhost:3000 in your browser

# 4. Build optimized production bundle
pnpm --filter web build
```

---

## 6. Next Steps & Roadmap

- **Milestone 2 (API Mode)**:
  - Implement `ApiDataSource` adhering to `docs/api/openapi.yaml`.
  - Connect to local `avero serve` daemon at `http://127.0.0.1:8787`.
  - Add scan job upload with SSE live progress events (`/api/jobs/{id}/events`).
- **Milestone 3 (Decompilation & Engines)**:
  - Integrate Monaco Editor for read-only C# decompiled output.
  - Implement engine manager (`/engines`) querying `avero engine list`.
- **Milestone 4 (Disassembly & Diffing)**:
  - Wire `/report/[reportId]/disassembly` against the live Rizin disassembly endpoint.
  - Build two-report diff comparison screen using `avero.diff/v1`.

## 7. Handover update — M2–M4 (this round)

**Status:** M2 (API mode), M3 (decompile/engines) and M4 (disassembly/diff) implemented and
verified. Production build green; **22 Vitest tests** pass, including a live integration test
against `avero serve`.

Delivered:

- `src/lib/data-source/api-data-source.ts` — typed client for `avero.api/v1`: health, report/evidence/strings/hex,
  multipart scan, job polling, SSE subscription, disassembly, decompile, engines + install, APK manifest,
  .NET facts, diff.
- Mode switching via `setAdapterSettings()`/`MODE_CHANGED_EVENT`; settings page tests connection and persists URL.
- Home renders an API scan panel (upload + options + SSE progress) in API mode.
- New screens: `engines`, `dotnet`, `signatures`, `disassembly`, `decompile`, `diff`; sidebar adapts to mode/kinds.
- Header/status bar show API readiness, core/API versions.
- `.github/workflows/web.yml` adds typecheck + tests + production build for `apps/web`.

Verification evidence (this session):

```
pnpm --filter web typecheck        -> clean
pnpm --filter web test             -> 8 files, 22 tests passed (1 live API integration)
pnpm --filter web build            -> 18 routes, compiled successfully
AVERO_API_URL=http://127.0.0.1:8787 pnpm --filter web test
  -> real scan of tests/fixtures/sample.apk, report/manifest/strings/hex/engines/disassembly verified
```

Remaining UI follow-ups: Monaco/CFG/call-graph polish, Playwright E2E + axe, saved views and
i18n; the API already exposes the needed contracts.

## 8. E2E, accessibility and screenshots

Playwright E2E + axe coverage is now part of the workbench:

- `apps/web/e2e/file-mode.spec.ts` — home/sample report, findings/evidence/sections,
  settings File→API mode persistence, unknown-report deep-link error state, axe
  serious/critical checks on home + overview.
- `apps/web/e2e/api-mode.spec.ts` — API scan over an SSE job, engines list, rizin
  disassembly rendering, report diff, decompile engine-missing error, all with Playwright
  route mocks (no daemon required in CI).

Commands:

```bash
pnpm --filter web e2e        # 11 Playwright tests (server built/started automatically)
pnpm --filter web e2e:headed # watch the browser
```

Latest local run: **11 passed (44s)**. Screenshots: `docs/screenshots/` (home file mode,
APK overview, settings mode switch).
