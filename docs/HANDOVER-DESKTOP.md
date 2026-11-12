# Desktop workbench handover (Tauri)

- **Location:** `apps/desktop`
- **Stack:** Tauri 2.12 + Vite 5 + React 19 + TypeScript strict
- **Contracts:** `avero.report/v1` (files), `avero.api/v1` (local daemon)
- **Status:** M1–M4 feature parity with the web workbench for the core screens (see below);
  built as a standalone Windows executable via `tauri build --no-bundle`.

## Why a separate desktop app

The web workbench (`apps/web`) is a Next.js app. Tauri needs static assets, and arbitrary
`/report/<id>` client routing is awkward with Next static export. The desktop app is a
standalone Vite/React SPA that reuses the same design tokens, data contracts and API client
patterns, and is bundled by Tauri (no Node runtime in production).

## Architecture

```
src/App.tsx     shell + all views (Home, report screens, engines, settings)
src/api.ts      avero.api/v1 fetch client + SSE job subscription
src/types.ts    avero.report/v1 + API types
src/styles.css  dark workbench design tokens (no Tailwind dependency)
src-tauri/      Tauri Rust shell, window config, CSP, icons
```

State model: `mode` (FILE/API), active `report`, optional `artifactBytes` (file mode hex),
tab routing in component state, recent reports + reports in `localStorage`.

Data modes:

- **FILE** — `<input type=file>` for `report.json`; optional artifact bytes for hex.
- **API** — `avero serve` REST calls; scans use multipart upload + SSE; jobs for decompile
  and engine install reuse the same SSE subscription helper.

## Endpoints used

`/api/health`, `/api/scans`, `/api/jobs/{id}` (+ `/events` SSE), `/api/reports/{id}`,
`/api/reports/{id}/strings`, `/api/reports/{id}/hex`, `/api/reports/{id}/disassembly`,
`/api/reports/{id}/decompile`, `/api/reports/{id}/apk-manifest`, `/api/reports/{id}/dotnet`,
`/api/engines`, `/api/engines/{id}/install`, `/api/diffs`.

## CORS

The core `avero serve` now echoes CORS origins for desktop WebView origins
(`tauri://localhost`, `http://tauri.localhost`, `https://tauri.localhost`) in addition to
configured/localhost origins, so the Tauri app can call the loopback API out of the box.

## Build & smoke test

```powershell
pnpm install
pnpm --filter desktop typecheck
pnpm --filter desktop build
cmd /c "call \"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat\" && pnpm --filter desktop tauri build --no-bundle"
# run
src-tauri\target\release\avero-desktop.exe
```

Smoke test: open a `report.json`, inspect Overview/Findings/Hex; start
`avero serve --port 8787`, switch Settings to API mode, scan an artifact and verify SSE
progress + report, engines and disassembly.

## Verified in this session

- `pnpm --filter desktop typecheck` clean.
- `pnpm --filter desktop build` — Vite production bundle.
- `pnpm tauri build --no-bundle` — release Windows executable (see build log).
- Manual smoke test of the executable with file mode + API mode (screenshots in docs/screenshots).

## Remaining follow-ups

- Ship installers: set `bundle.targets` to `nsis`/`msi` and sign the binaries.
- Add a Tauri CI job (Windows) and attach the desktop artifact to releases.
- Optional native commands: auto-start/stop `avero serve`, native file dialogs, tray icon.
- Reuse web E2E patterns for desktop via Tauri WebDriver (tauri-driver).
