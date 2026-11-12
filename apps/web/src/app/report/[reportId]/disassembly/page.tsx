"use client";

/**
 * @file page.tsx
 * @brief Rizin disassembly route (/report/[reportId]/disassembly) — API mode only.
 */

import React, { useCallback, useEffect, useState, use } from "react";
import { TerminalSquare, Play, Loader2, AlertCircle, Server } from "lucide-react";
import { useReport } from "@/lib/report-context";
import type { AveroReport } from "@/types/report";
import type { DisassemblyPage as DisassemblyResult } from "@/types/api";

interface DisassemblyPageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Disassembly screen: address seek, instruction count and rizin-backed listing.
 */
export default function DisassemblyPage({ params }: DisassemblyPageProps) {
  const resolvedParams = use(params);
  const { activeReport, loadReportById, mode, source } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);
  const [address, setAddress] = useState("");
  const [limit, setLimit] = useState(64);
  const [analyze, setAnalyze] = useState(false);
  const [result, setResult] = useState<DisassemblyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!report || report.artifact.id !== resolvedParams.reportId) {
      loadReportById(resolvedParams.reportId).then((loaded) => {
        if (loaded) setReport(loaded);
      });
    }
  }, [resolvedParams.reportId, report, loadReportById]);

  const run = useCallback(async () => {
    if (!report || !source.getDisassembly) return;
    setLoading(true);
    setError(null);
    try {
      const page = await source.getDisassembly(report.artifact.id, {
        start: address.trim() || undefined,
        limit,
        analyze,
      });
      setResult(page);
    } catch (disassemblyError: unknown) {
      setError(
        disassemblyError instanceof Error ? disassemblyError.message : "Disassembly failed",
      );
    } finally {
      setLoading(false);
    }
  }, [report, source, address, limit, analyze]);

  useEffect(() => {
    if (mode === "API" && report && !result) {
      void run();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, report]);

  if (mode !== "API") {
    return (
      <div className="p-4 rounded-card bg-panel border border-border space-y-2">
        <div className="flex items-center space-x-2 text-high text-sm font-semibold">
          <Server className="w-4 h-4" />
          <span>Disassembly requires API mode</span>
        </div>
        <p className="text-xs text-muted">
          Start <code className="text-accent">avero serve</code> and switch to API mode in Settings.
          The daemon uses the installed rizin engine.
        </p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-3">
        <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        <div className="text-xs text-muted">Loading report…</div>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text flex items-center space-x-2">
          <TerminalSquare className="w-5 h-5 text-accent" />
          <span>Disassembly</span>
        </h1>
        <p className="text-xs text-muted">
          rizin sidecar output at an address (default <code className="font-mono">entry0</code>).
          Read-only; the artifact is never executed.
        </p>
      </div>

      <form
        onSubmit={(event) => {
          event.preventDefault();
          void run();
        }}
        className="p-3 rounded-card bg-panel border border-border flex flex-wrap items-end gap-3"
      >
        <label className="space-y-1 text-xs">
          <span className="text-muted block">Start address (hex or decimal)</span>
          <input
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            placeholder="0x140001000 (default: entry0)"
            className="bg-bg border border-border rounded-input px-2.5 py-1.5 text-text font-mono w-64 focus:border-accent focus:outline-none"
          />
        </label>
        <label className="space-y-1 text-xs">
          <span className="text-muted block">Instructions</span>
          <input
            type="number"
            min={1}
            max={1000}
            value={limit}
            onChange={(event) => setLimit(Number(event.target.value))}
            className="bg-bg border border-border rounded-input px-2.5 py-1.5 text-text font-mono w-24 focus:border-accent focus:outline-none"
          />
        </label>
        <label className="flex items-center space-x-2 text-xs text-muted pb-1.5">
          <input type="checkbox" checked={analyze} onChange={(event) => setAnalyze(event.target.checked)} />
          <span>Run rizin analysis (aa, slower)</span>
        </label>
        <button
          type="submit"
          disabled={loading}
          className="px-3 py-2 rounded-input bg-accent/10 hover:bg-accent/20 disabled:opacity-50 text-accent text-xs font-semibold border border-accent/30 flex items-center space-x-1.5"
        >
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
          <span>{loading ? "Disassembling…" : "Disassemble"}</span>
        </button>
      </form>

      {error && (
        <div className="flex items-start space-x-2 p-3 rounded-input bg-critical/10 border border-critical/30 text-critical text-xs">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className="rounded-card bg-panel border border-border overflow-hidden">
          <div className="px-4 py-2 border-b border-border text-[11px] text-muted font-mono">
            base: {result.address} · {result.items.length} instruction(s)
          </div>
          <table className="w-full text-xs font-mono">
            <thead className="bg-panel-2 text-muted uppercase tracking-wider text-[10px]">
              <tr>
                <th className="text-left px-3 py-2">Address</th>
                <th className="text-left px-3 py-2">Bytes</th>
                <th className="text-left px-3 py-2">Instruction</th>
                <th className="text-right px-3 py-2">Size</th>
                <th className="text-right px-3 py-2">Kind</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {result.items.map((instruction, index) => (
                <tr key={`${instruction.address}-${index}`} className="hover:bg-panel-2/50">
                  <td className="px-3 py-1.5 text-accent">0x{instruction.address.toString(16)}</td>
                  <td className="px-3 py-1.5 text-muted">{instruction.bytes_hex || ""}</td>
                  <td className="px-3 py-1.5 text-text">
                    {instruction.mnemonic} {instruction.operands}
                  </td>
                  <td className="px-3 py-1.5 text-right text-muted">{instruction.size ?? ""}</td>
                  <td className="px-3 py-1.5 text-right text-muted">{instruction.kind || ""}</td>
                </tr>
              ))}
              {result.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-muted">
                    No instructions at this address (install rizin first: <code>avero engine install rizin</code>).
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
