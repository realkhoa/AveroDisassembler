# API contract (`avero.api/v1`)

The UI workbench consumes the core through a **local-only** API. This directory defines the
contract so the UI and core can be developed independently.

**Status: implemented in v0.11.0.** Run `avero serve` (loopback `127.0.0.1:8787` by default)
and the UI can switch from file mode to API mode. All read endpoints plus scan and
decompile, disassembly and job endpoints are live: `POST /api/reports/{id}/decompile`
supports `engine` values `ilspycmd` (.NET) and `ghidra` (native, JDK 25+ required), and
`GET /api/reports/{id}/disassembly` returns rizin-backed instructions. Diff returns `501`
until the next phase (report diff is live: `POST /api/diffs`, `avero.diff/v1`).

| File | Purpose |
|---|---|
| [`openapi.yaml`](openapi.yaml) | OpenAPI 3.1 specification (`avero.api/v1`) |
| [`sample-report.json`](sample-report.json) | Real `avero.report/v1` report generated from `tests/fixtures/sample.apk` |

## Modes

1. **File mode** (works today): the UI reads a `report.json` produced by
   `avero scan <file> --json`. No server is required.
2. **API mode** (works today): run `avero serve --port 8787`, then use the endpoints in
   `openapi.yaml`. The server binds to loopback only and stores uploads/reports under
   `.avero/serve/` (git-ignored).

```powershell
target\release\avero.exe serve --port 8787
# from the UI: GET http://127.0.0.1:8787/api/health
```

## Regenerating the sample report

```powershell
target\release\avero.exe scan tests\fixtures\sample.apk --json --no-cache |
  Set-Content docs\api\sample-report.json -Encoding UTF8
```

Remove or normalize `artifact.path` before committing so no absolute local paths leak into
the repository.

## Conventions

- IDs are stable strings. `reportId` is the artifact SHA-256 (64 lowercase hex chars).
- Pagination returns `{items, next_cursor, total}` with opaque cursors; `offset` is accepted
  for strings as a convenience.
- Errors are `{"error":{"code":"...","message":"...","details":{}}}` with proper status
  codes; the UI must render `message` and offer retry where sensible.
- Hex responses are base64 (`bytes_base64`) and capped at 64 KiB per request.
- The API never returns local filesystem paths except the informational `artifact.path`.
- Streaming: `GET /api/jobs/{jobId}/events` is Server-Sent Events; the stream closes after
  `done` or `error`.
- The API binds to loopback only, rejects non-loopback Host/Origin, and has no
  authentication (local single-user tool).
- Any contract change requires a version bump (`avero.api/v2`) plus a note in
  `docs/IMPLEMENTATION-STATUS.md`.

## UI responsibilities

- Validate `schema_id`; show a banner for unknown versions and render best-effort.
- Never send artifacts or reports to remote hosts.
- Request hex slices on demand (paging), not whole artifacts.
- Treat `POST /api/scans`, `POST /api/decompile` and engine installation as explicit,
  confirmed user actions.

See [`docs/UI-SPEC.md`](../UI-SPEC.md) for screen-level requirements and acceptance criteria.
