# Research data

This directory contains the raw evidence behind the [research report](../docs/RE-RESEARCH-REPORT.md). It is not part of the shipped product.

## Snapshot

- **Date**: 2026-11-12 (Asia/Bangkok)
- **Sources**: GitHub GraphQL API (batched queries), upstream awesome lists, README/package manifests of reference projects.
- **Scope**: 112 repositories (deduplicated), 4 awesome-reverse-engineering lists, 2 architecture references.

## Files

| File | Description |
|---|---|
| `repos-categorized.csv` | Normalized table: category, repository, stars, license, last push, latest release, language, archived flag, description |
| `repos.json` | Same dataset as JSON (112 repositories) |
| `sources/github-body-{a,b,c}.json` | GraphQL request bodies |
| `sources/github-repos-{a,b,c}.json` | Raw GitHub API responses (may contain `errors` for renamed repositories) |
| `sources/awesome-re-*.md` | Downloaded awesome lists (original authors' CC0/MIT licenses) |
| `sources/rea-package.json` | REA package manifest used for architecture analysis |

## Reproducing

1. Requires an authenticated `gh` CLI (GraphQL API) and `curl`.
2. Re-run the queries:
   ```powershell
   gh api graphql --input research/sources/github-body-a.json
   ```
3. Normalize responses into CSV/JSON the same way the snapshot was produced.

## Known limitations

- `stars`/`latestRelease` are a point-in-time snapshot; projects change.
- `NOASSERTION` means GitHub could not detect a license — it does **not** mean there is no license.
- Four initial queries used outdated slugs and were corrected: `dnSpyEx/dnSpy`, `x64dbg/ScyllaHide`, `hasherezade/pe-bear`, `nowsecure/r2frida`.
- Some star counts are unusually high (notably REA, ~453k); they are not used as a quality metric.
- Awesome lists can lag behind upstream; cross-check release tags in the CSV.
