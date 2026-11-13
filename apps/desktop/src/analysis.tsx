/**
 * Ghidra/IDA-style analysis workspace: function explorer + call map, interactive
 * disassembly with cross-reference jumps, and an editable hex viewer with patched-copy export.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./api";
import { annotationFor, displayName, functionAt } from "./annotations";
import type { AnnotationMap, FunctionInfo, Instruction, Report } from "./types";

/* ------------------------------------------------------------------ */
/* function map (call graph)                                           */
/* ------------------------------------------------------------------ */

function FunctionMap({
  functions,
  annotations,
  onJump,
  selected,
  height = 360,
}: {
  functions: FunctionInfo[];
  annotations: AnnotationMap;
  onJump: (address: number) => void;
  selected?: number | null;
  height?: number;
}) {
  const nodes = useMemo(() => functions.slice(0, 160), [functions]);
  const cellWidth = 148;
  const cellHeight = 64;
  const columns = Math.max(1, Math.ceil(Math.sqrt(nodes.length)));
  const rows = Math.ceil(nodes.length / columns);
  const width = columns * cellWidth;
  const svgHeight = Math.max(height, rows * cellHeight);
  const indexByAddress = useMemo(() => {
    const map = new Map<number, number>();
    nodes.forEach((fn, index) => map.set(fn.address, index));
    return map;
  }, [nodes]);

  const position = (index: number) => ({
    x: (index % columns) * cellWidth + cellWidth / 2,
    y: Math.floor(index / columns) * cellHeight + cellHeight / 2,
  });

  const edges: { from: number; to: number }[] = [];
  for (const fn of nodes) {
    for (const reference of fn.callrefs) {
      const target = indexByAddress.get(reference.to);
      const source = indexByAddress.get(fn.address);
      if (target !== undefined && source !== undefined && target !== source) {
        edges.push({ from: source, to: target });
      }
    }
  }

  if (nodes.length === 0) {
    return <div className="muted small">No functions available for a call map.</div>;
  }

  return (
    <div style={{ overflow: "auto", maxHeight: height, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--panel)" }}>
      <svg width={width} height={svgHeight} role="img" aria-label="Function call map">
        {edges.map((edge, index) => {
          const a = position(edge.from);
          const b = position(edge.to);
          return (
            <line
              key={`edge-${index}`}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke="#2f3a47"
              strokeWidth={1}
            />
          );
        })}
        {nodes.map((fn, index) => {
          const point = position(index);
          const isSelected = selected === fn.address;
          const label = displayName(annotations, fn.address, fn.name);
          return (
            <g
              key={fn.address}
              transform={`translate(${point.x - cellWidth / 2 + 6},${point.y - 18})`}
              onClick={() => onJump(fn.address)}
              style={{ cursor: "pointer" }}
            >
              <title>{`${label} @ 0x${fn.address.toString(16)} · ${fn.size} bytes`}</title>
              <rect
                width={cellWidth - 12}
                height={40}
                rx={6}
                fill={isSelected ? "rgba(76,194,255,.15)" : "var(--panel-2)"}
                stroke={isSelected ? "var(--accent)" : "var(--border)"}
              />
              <text x={7} y={16} fill="var(--text)" fontSize={10} fontFamily="var(--mono)">
                {label.length > 18 ? `${label.slice(0, 17)}…` : label}
              </text>
              <text x={7} y={30} fill="var(--muted)" fontSize={9} fontFamily="var(--mono)">
                0x{fn.address.toString(16)} · {fn.size}b
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* function explorer / editor                                          */
/* ------------------------------------------------------------------ */

export function FunctionsView({
  report,
  mode,
  functions,
  loading,
  error,
  annotations,
  onAnnotate,
  onJump,
  onRefresh,
}: {
  report: Report;
  mode: "FILE" | "API";
  functions: FunctionInfo[];
  loading: boolean;
  error: string | null;
  annotations: AnnotationMap;
  onAnnotate: (address: number, patch: { name?: string; comment?: string; prototype?: string }) => void;
  onJump: (address: number) => void;
  onRefresh: () => void;
}) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<number | null>(null);
  const [name, setName] = useState("");
  const [comment, setComment] = useState("");
  const [prototype, setPrototype] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (functions.length > 0 && selected === null) setSelected(functions[0].address);
  }, [functions, selected]);

  const current = functions.find((fn) => fn.address === selected) || null;
  const annotation = selected !== null ? annotationFor(annotations, selected) : undefined;

  useEffect(() => {
    setName(annotation?.name || current?.name || "");
    setComment(annotation?.comment || "");
    setPrototype(annotation?.prototype || current?.signature || "");
  }, [selected, annotation, current]);

  const filtered = functions.filter((fn) => {
    if (!query.trim()) return true;
    const needle = query.toLowerCase();
    return (
      fn.name.toLowerCase().includes(needle) ||
      displayName(annotations, fn.address, fn.name).toLowerCase().includes(needle) ||
      `0x${fn.address.toString(16)}`.includes(needle)
    );
  });

  const save = () => {
    if (selected === null) return;
    onAnnotate(selected, { name: name.trim() || undefined, comment: comment.trim() || undefined, prototype: prototype.trim() || undefined });
    setSaved(true);
    window.setTimeout(() => setSaved(false), 1200);
  };

  if (mode !== "API") {
    return (
      <div className="card">
        <h2 className="section-title">Function analysis requires the embedded core</h2>
        <p className="muted small">Switch to API mode (default in the desktop app) so the embedded core can run rizin analysis on the artifact.</p>
      </div>
    );
  }

  const targets = current?.callrefs.filter((reference) => reference.kind === "CALL") || [];

  return (
    <div className="grid" style={{ gridTemplateColumns: "320px 1fr", alignItems: "start" }}>
      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: 10, borderBottom: "1px solid var(--border)" }}>
          <input
            className="input"
            style={{ width: "100%" }}
            placeholder={`Filter ${functions.length} functions…`}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
        <div className="list" style={{ maxHeight: "62vh" }}>
          {filtered.slice(0, 2000).map((fn) => (
            <button
              key={fn.address}
              className={`row-button ${selected === fn.address ? "active" : ""}`}
              onClick={() => setSelected(fn.address)}
              title={`0x${fn.address.toString(16)} · ${fn.size} bytes`}
            >
              <span className="mono small muted">0x{fn.address.toString(16)}</span>
              <span className="truncate" style={{ flex: 1 }}>
                {displayName(annotations, fn.address, fn.name)}
              </span>
              <span className="muted small">{fn.size}b</span>
            </button>
          ))}
          {loading && <div className="muted small" style={{ padding: 10 }}>Analyzing functions…</div>}
          {!loading && filtered.length === 0 && <div className="muted small" style={{ padding: 10 }}>No functions.</div>}
        </div>
      </div>

      <div className="grid">
        <div className="card">
          <div className="flex-between mb">
            <div>
              <h2 className="section-title" style={{ margin: 0 }}>
                {selected !== null ? displayName(annotations, selected, current?.name || "function") : "Select a function"}
              </h2>
              {selected !== null && <div className="mono small muted">0x{selected.toString(16)} · {current?.size ?? 0} bytes</div>}
            </div>
            <div className="row">
              <button className="button sm" onClick={onRefresh} disabled={loading}>Re-analyze</button>
              {selected !== null && <button className="button primary sm" onClick={() => onJump(selected)}>Open disassembly</button>}
            </div>
          </div>

          {selected !== null && (
            <div className="grid">
              <div className="row">
                <div className="field" style={{ flex: 1 }}>
                  <label>Function name</label>
                  <input className="input mono" value={name} onChange={(event) => setName(event.target.value)} />
                </div>
                <div className="field" style={{ flex: 1 }}>
                  <label>Prototype</label>
                  <input className="input mono" value={prototype} onChange={(event) => setPrototype(event.target.value)} />
                </div>
              </div>
              <div className="field">
                <label>Comment</label>
                <textarea className="input" rows={3} value={comment} onChange={(event) => setComment(event.target.value)} />
              </div>
              <div className="row">
                <button className="button primary sm" onClick={save}>{saved ? "Saved" : "Save annotation"}</button>
                <span className="muted small">Stored locally per artifact (rename/comment only; no binary patch).</span>
              </div>
            </div>
          )}
        </div>

        {current && (
          <div className="grid grid-2">
            <div className="card">
              <h2 className="section-title">Calls from this function ({targets.length})</h2>
              <div className="list" style={{ maxHeight: 220 }}>
                {targets.map((reference, index) => {
                  const targetName = functionAt(functions, reference.to)?.name || `sub_${reference.to.toString(16)}`;
                  return (
                    <button key={`${reference.from}-${reference.to}-${index}`} className="row-button" onClick={() => onJump(reference.to)}>
                      <span className="mono small muted">0x{reference.from.toString(16)}</span>
                      <span className="mono small">→</span>
                      <span className="truncate" style={{ flex: 1 }}>{displayName(annotations, reference.to, targetName)}</span>
                      <span className="mono small muted">0x{reference.to.toString(16)}</span>
                    </button>
                  );
                })}
                {targets.length === 0 && <div className="muted small" style={{ padding: 10 }}>No call references.</div>}
              </div>
            </div>
            <div className="card">
              <h2 className="section-title">Callers</h2>
              <div className="list" style={{ maxHeight: 220 }}>
                {functions
                  .filter((fn) => fn.callrefs.some((reference) => reference.kind === "CALL" && reference.to === selected))
                  .slice(0, 200)
                  .map((fn) => (
                    <button key={fn.address} className="row-button" onClick={() => onJump(fn.address)}>
                      <span className="truncate" style={{ flex: 1 }}>{displayName(annotations, fn.address, fn.name)}</span>
                      <span className="mono small muted">0x{fn.address.toString(16)}</span>
                    </button>
                  ))}
              </div>
            </div>
          </div>
        )}

        <div className="card">
          <div className="flex-between mb">
            <h2 className="section-title" style={{ margin: 0 }}>Function map (call graph)</h2>
            <span className="muted small">{Math.min(functions.length, 160)} nodes · click to jump</span>
          </div>
          <FunctionMap functions={functions} annotations={annotations} selected={selected} onJump={onJump} />
        </div>

        {error && <div className="alert error">{error}</div>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* disassembly workspace                                               */
/* ------------------------------------------------------------------ */

export function DisassemblyWorkspace({
  report,
  apiUrl,
  annotations,
  functions,
  initialAddress,
  onJump,
}: {
  report: Report;
  apiUrl: string;
  annotations: AnnotationMap;
  functions: FunctionInfo[];
  initialAddress?: string;
  onJump: (address: number) => void;
}) {
  const [address, setAddress] = useState(initialAddress || "");
  const [limit, setLimit] = useState(96);
  const [analyze, setAnalyze] = useState(false);
  const [items, setItems] = useState<Instruction[]>([]);
  const [base, setBase] = useState("entry0");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (initialAddress) setAddress(initialAddress);
  }, [initialAddress]);

  const run = useCallback(async (start?: string) => {
    setLoading(true);
    setError(null);
    try {
      const page = await api.getDisassembly(apiUrl, report.artifact.id, {
        start: (start ?? address).trim() || undefined,
        limit,
        analyze,
      });
      setItems(page.items);
      setBase(page.address);
    } catch (runError: unknown) {
      setError(runError instanceof Error ? runError.message : "disassembly failed");
    } finally {
      setLoading(false);
    }
  }, [apiUrl, report.artifact.id, address, limit, analyze]);

  useEffect(() => {
    if (initialAddress) {
      setAddress(initialAddress);
      void run(initialAddress);
    } else {
      void run();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialAddress]);

  const jumpTo = (target: number) => {
    setAddress(`0x${target.toString(16)}`);
    onJump(target);
  };

  return (
    <div className="grid">
      <div className="card">
        <div className="row">
          <div className="field">
            <label>Address (hex/dec, default entry0)</label>
            <input className="input mono" value={address} onChange={(event) => setAddress(event.target.value)} style={{ width: 220 }} />
          </div>
          <div className="field">
            <label>Instructions</label>
            <input className="input mono" type="number" value={limit} onChange={(event) => setLimit(Number(event.target.value))} style={{ width: 90 }} />
          </div>
          <label className="small muted flex items-center gap-8">
            <input type="checkbox" checked={analyze} onChange={(event) => setAnalyze(event.target.checked)} /> rizin analysis
          </label>
          <button className="button primary" onClick={() => void run()} disabled={loading}>{loading ? "Disassembling…" : "Disassemble"}</button>
          <span className="muted small mono">base {base}</span>
        </div>
        {error && <div className="alert error mt">{error}</div>}
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 280px", alignItems: "start" }}>
        <div className="table-scroll">
          <table className="table">
            <thead>
              <tr><th>Address</th><th>Bytes</th><th>Instruction</th><th>Size</th><th>Kind</th></tr>
            </thead>
            <tbody>
              {items.map((item, index) => {
                const targetMatch = item.operands?.match(/0x([0-9a-fA-F]+)/);
                const target = targetMatch ? parseInt(targetMatch[1], 16) : null;
                const targetFunction = target !== null ? functionAt(functions, target) : undefined;
                const startFunction = functionAt(functions, item.address);
                const isFunctionStart = startFunction?.address === item.address;
                return (
                  <tr key={`${item.address}-${index}`} className={isFunctionStart ? "hex-branch" : undefined}>
                    <td className="mono">
                      <button className="link-button" onClick={() => jumpTo(item.address)} title="Jump here">0x{item.address.toString(16)}</button>
                    </td>
                    <td className="mono muted">{item.bytes_hex}</td>
                    <td className="mono">
                      <span className={item.kind === "call" ? "text-accent" : ""}>{item.mnemonic}</span>{" "}
                      {target !== null && targetFunction ? (
                        <button className="link-button" onClick={() => jumpTo(target)} title={`Jump to 0x${target.toString(16)}`}>
                          {displayName(annotations, target, targetFunction.name)}
                          <span className="muted small"> (0x{target.toString(16)})</span>
                        </button>
                      ) : (
                        item.operands
                      )}
                    </td>
                    <td className="mono">{item.size}</td>
                    <td className="mono muted">{item.kind}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div className="card">
          <h2 className="section-title">Nearby functions</h2>
          <div className="list" style={{ maxHeight: "58vh" }}>
            {functions
              .slice()
              .sort((a, b) => Math.abs(a.address - items[0]?.address || 0) - Math.abs(b.address - items[0]?.address || 0))
              .slice(0, 80)
              .map((fn) => (
                <button key={fn.address} className="row-button" onClick={() => jumpTo(fn.address)}>
                  <span className="mono small muted">0x{fn.address.toString(16)}</span>
                  <span className="truncate" style={{ flex: 1 }}>{displayName(annotations, fn.address, fn.name)}</span>
                </button>
              ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* editable hex viewer                                                 */
/* ------------------------------------------------------------------ */

const PAGE_SIZE = 512;

export function HexWorkspace({
  report,
  mode,
  apiUrl,
  bytes,
  onBytes,
}: {
  report: Report;
  mode: "FILE" | "API";
  apiUrl: string;
  bytes: Uint8Array | null;
  onBytes: (bytes: Uint8Array) => void;
}) {
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<Uint8Array | null>(null);
  const [jump, setJump] = useState("0");
  const [selected, setSelected] = useState<number | null>(null);
  const [hexValue, setHexValue] = useState("");
  const [edits, setEdits] = useState<Record<number, number>>({});
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const load = useCallback(async (target: number) => {
    setError(null);
    setPage(null);
    try {
      if (mode === "API") {
        setPage(await api.getHex(apiUrl, report.artifact.id, target, PAGE_SIZE));
      } else if (bytes) {
        setPage(bytes.subarray(target, target + PAGE_SIZE));
      } else {
        setPage(null);
        setError("No artifact bytes attached for this report. Attach the original binary first.");
      }
    } catch (loadError: unknown) {
      setError(loadError instanceof Error ? loadError.message : "hex read failed");
    }
  }, [mode, apiUrl, report.artifact.id, bytes]);

  useEffect(() => { void load(offset); }, [load, offset]);

  const displayValue = (absolute: number, original: number) =>
    edits[absolute] !== undefined ? edits[absolute] : original;

  const applyByte = () => {
    if (selected === null) return;
    const normalized = hexValue.replace(/[^0-9a-fA-F]/g, "");
    if (normalized.length === 0 || normalized.length > 2) {
      setError("Enter 1–2 hex characters (e.g. 90 or 4D).");
      return;
    }
    const value = parseInt(normalized, 16);
    setEdits((current) => ({ ...current, [selected]: value }));
    setHexValue("");
    setError(null);
    setStatus(`Patched 0x${selected.toString(16)} = 0x${value.toString(16).padStart(2, "0")}`);
  };

  const exportPatched = async () => {
    setExporting(true);
    setError(null);
    setStatus(null);
    try {
      let full: Uint8Array;
      if (mode === "FILE") {
        if (!bytes) throw new Error("Attach the original artifact first.");
        full = bytes.slice();
      } else {
        full = await api.getArtifactBytes(apiUrl, report.artifact.id);
      }
      for (const [key, value] of Object.entries(edits)) {
        const index = Number(key);
        if (index >= 0 && index < full.length) full[index] = value;
      }
      const blob = new Blob([full as unknown as BlobPart], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      const name = report.artifact.path.split(/[/\\]/).pop() || "artifact";
      anchor.href = url;
      anchor.download = `${name}.patched`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setStatus(`Exported patched copy with ${Object.keys(edits).length} byte change(s).`);
    } catch (exportError: unknown) {
      setError(exportError instanceof Error ? exportError.message : "export failed");
    } finally {
      setExporting(false);
    }
  };

  const rows: React.ReactNode[] = [];
  if (page) {
    for (let index = 0; index < page.length; index += 16) {
      const cells: React.ReactNode[] = [];
      for (let inner = 0; inner < 16; inner += 1) {
        const relative = index + inner;
        if (relative >= page.length) break;
        const absolute = offset + relative;
        const value = displayValue(absolute, page[relative]);
        const isEdited = edits[absolute] !== undefined;
        const isSelected = selected === absolute;
        cells.push(
          <button
            key={absolute}
            className={`hex-byte ${isEdited ? "edited" : ""} ${isSelected ? "selected" : ""}`}
            onClick={() => {
              setSelected(absolute);
              setHexValue(value.toString(16).padStart(2, "0"));
            }}
            title={`0x${absolute.toString(16)}`}
          >
            {value.toString(16).padStart(2, "0")}
          </button>,
        );
      }
      rows.push(
        <div className="hex-row" key={offset + index}>
          <span className="hex-address">{(offset + index).toString(16).padStart(8, "0")}</span>
          <span className="hex-cell-group">{cells}</span>
          <span className="hex-ascii">
            {Array.from(page.subarray(index, index + 16))
              .map((_, inner) => {
                const absolute = offset + index + inner;
                if (absolute >= offset + page.length) return "";
                const value = displayValue(absolute, page[index + inner]);
                return value >= 32 && value < 127 ? String.fromCharCode(value) : ".";
              })
              .join("")}
          </span>
        </div>,
      );
    }
  }

  return (
    <div className="grid">
      <div className="card">
        <div className="row">
          <div className="field">
            <label>Offset (hex)</label>
            <input className="input mono" value={jump} onChange={(event) => setJump(event.target.value)} style={{ width: 140 }} />
          </div>
          <button className="button" onClick={() => { const parsed = parseInt(jump.replace(/^0x/, ""), 16); if (!Number.isNaN(parsed)) { setOffset(Math.max(0, parsed)); } }}>Go</button>
          <button className="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Prev</button>
          <button className="button" onClick={() => setOffset(offset + PAGE_SIZE)}>Next</button>
          {mode === "FILE" && (
            <>
              <button className="button" onClick={() => input.current?.click()}>{bytes ? "Replace artifact bytes" : "Attach artifact bytes"}</button>
              <input
                ref={input}
                type="file"
                style={{ display: "none" }}
                onChange={async (event) => {
                  const file = event.target.files?.[0];
                  if (file) onBytes(new Uint8Array(await file.arrayBuffer()));
                  event.target.value = "";
                }}
              />
            </>
          )}
          <span className="muted small">report size {((report.artifact.size / 1024)).toFixed(1)} KB · page {PAGE_SIZE} B</span>
        </div>

        <div className="row mt">
          <span className="muted small">Selected byte:</span>
          <span className="mono small">{selected !== null ? `0x${selected.toString(16)}` : "—"}</span>
          <input className="input mono" value={hexValue} onChange={(event) => setHexValue(event.target.value)} style={{ width: 70 }} placeholder="4D" maxLength={2} />
          <button className="button sm" onClick={applyByte} disabled={selected === null}>Apply byte</button>
          <button className="button sm" onClick={() => { setEdits({}); setStatus("Reverted all local edits."); }} disabled={Object.keys(edits).length === 0}>Revert edits</button>
          <button className="button primary sm" onClick={() => void exportPatched()} disabled={exporting}>{exporting ? "Exporting…" : `Export patched copy (${Object.keys(edits).length})`}</button>
        </div>
        {error && <div className="alert error mt">{error}</div>}
        {status && <div className="alert info mt">{status}</div>}
      </div>

      <div className="card" style={{ padding: 0 }}>
        {!page ? (
          <div className="muted small" style={{ padding: 16 }}>No bytes loaded.</div>
        ) : (
          <div className="hex-grid">{rows}</div>
        )}
      </div>
    </div>
  );
}
