"use client";

/**
 * @file page.tsx
 * @brief Report diff route (/report/[reportId]/diff) — API mode only (M4).
 */

import React, { useEffect, useState, use } from "react";
import { GitCompare, Play, Loader2, AlertCircle, Server, Plus, Minus } from "lucide-react";
import { useReport } from "@/lib/report-context";
import type { AveroReport } from "@/types/report";
import type { DiffResult } from "@/types/api";

interface DiffPageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Two-report comparison screen backed by `POST /api/diffs` (avero.diff/v1).
 */
export default function DiffPage({ params }: DiffPageProps) {
  const resolvedParams = use(params);
  const { activeReport, loadReportById, mode, source } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);
  const [oldReport, setOldReport] = useState("");
  const [newReport, setNewReport] = useState("");
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!report || report.artifact.id !== resolvedParams.reportId) {
      loadReportById(resolvedParams.reportId).then((loaded) => {
        if (loaded) {
          setReport(loaded);
          setNewReport(loaded.artifact.id);
        }
      });
    } else if (!newReport) {
      setNewReport(report.artifact.id);
    }
  }, [resolvedParams.reportId, report, loadReportById, newReport]);

  if (mode !== "API") {
    return (
      <div className="p-4 rounded-card bg-panel border border-border space-y-2">
        <div className="flex items-center space-x-2 text-high text-sm font-semibold">
          <Server className="w-4 h-4" />
          <span>Report diff requires API mode</span>
        </div>
        <p className="text-xs text-muted">
          Start <code className="text-accent">avero serve</code> and switch to API mode in Settings.
          Scan both artifacts first so the daemon can compare them.
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

  const run = async () => {
    if (!source.diff) return;
    setLoading(true);
    setError(null);
    setDiff(null);
    try {
      setDiff(await source.diff(oldReport.trim(), newReport.trim()));
    } catch (diffError: unknown) {
      setError(diffError instanceof Error ? diffError.message : "Diff failed");
    } finally {
      setLoading(false);
    }
  };

  const listSection = (
    title: string,
    added: string[],
    removed: string[],
  ) => (
    <div className="p-3 rounded-card bg-panel border border-border space-y-2">
      <h3 className="text-xs font-semibold text-text uppercase tracking-wider">{title}</h3>
      <div className="space-y-1 text-xs">
        {added.map((item) => (
          <div key={`add-${item}`} className="flex items-center space-x-1.5 text-low font-mono">
            <Plus className="w-3 h-3" />
            <span className="truncate">{item}</span>
          </div>
        ))}
        {removed.map((item) => (
          <div key={`del-${item}`} className="flex items-center space-x-1.5 text-critical font-mono">
            <Minus className="w-3 h-3" />
            <span className="truncate">{item}</span>
          </div>
        ))}
        {added.length === 0 && removed.length === 0 && (
          <div className="text-muted">No changes</div>
        )}
      </div>
    </div>
  );

  return (
    <div className="space-y-4 max-w-6xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text flex items-center space-x-2">
          <GitCompare className="w-5 h-5 text-accent" />
          <span>Report Diff</span>
        </h1>
        <p className="text-xs text-muted">
          Compare two stored reports (<code className="font-mono">avero.diff/v1</code>): findings,
          sections, imports/exports, signature rules and metadata changes.
        </p>
      </div>

      <form
        onSubmit={(event) => {
          event.preventDefault();
          void run();
        }}
        className="p-3 rounded-card bg-panel border border-border flex flex-wrap items-end gap-3"
      >
        <label className="space-y-1 text-xs flex-1 min-w-[18rem]">
          <span className="text-muted block">Old report id (SHA-256)</span>
          <input
            value={oldReport}
            onChange={(event) => setOldReport(event.target.value)}
            placeholder="artifact SHA-256"
            className="w-full bg-bg border border-border rounded-input px-2.5 py-1.5 text-text font-mono focus:border-accent focus:outline-none"
          />
        </label>
        <label className="space-y-1 text-xs flex-1 min-w-[18rem]">
          <span className="text-muted block">New report id (SHA-256)</span>
          <input
            value={newReport}
            onChange={(event) => setNewReport(event.target.value)}
            placeholder="artifact SHA-256"
            className="w-full bg-bg border border-border rounded-input px-2.5 py-1.5 text-text font-mono focus:border-accent focus:outline-none"
          />
        </label>
        <button
          type="submit"
          disabled={loading || !oldReport.trim() || !newReport.trim()}
          className="px-3 py-2 rounded-input bg-accent/10 hover:bg-accent/20 disabled:opacity-50 text-accent text-xs font-semibold border border-accent/30 flex items-center space-x-1.5"
        >
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
          <span>{loading ? "Comparing…" : "Compare"}</span>
        </button>
      </form>

      {error && (
        <div className="flex items-start space-x-2 p-3 rounded-input bg-critical/10 border border-critical/30 text-critical text-xs">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {diff && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3 rounded-card bg-panel border border-border">
              <div className="text-[11px] text-muted uppercase">Size delta</div>
              <div className="text-sm font-mono text-text">
                {diff.size_delta >= 0 ? "+" : ""}
                {diff.size_delta} bytes
              </div>
            </div>
            <div className="p-3 rounded-card bg-panel border border-border">
              <div className="text-[11px] text-muted uppercase">Findings added</div>
              <div className="text-sm font-mono text-low">+{diff.findings.counts.added}</div>
            </div>
            <div className="p-3 rounded-card bg-panel border border-border">
              <div className="text-[11px] text-muted uppercase">Findings removed</div>
              <div className="text-sm font-mono text-critical">−{diff.findings.counts.removed}</div>
            </div>
            <div className="p-3 rounded-card bg-panel border border-border">
              <div className="text-[11px] text-muted uppercase">Unchanged</div>
              <div className="text-sm font-mono text-text">{diff.findings.counts.unchanged}</div>
            </div>
          </div>

          <div className="p-3 rounded-card bg-panel border border-border space-y-2">
            <h3 className="text-xs font-semibold text-text uppercase tracking-wider">Findings changed</h3>
            <div className="space-y-1 text-xs">
              {diff.findings.added.map((finding) => (
                <div key={finding.id} className="flex items-center space-x-1.5 text-low">
                  <Plus className="w-3 h-3 shrink-0" />
                  <span className="uppercase text-[10px] font-semibold w-16 shrink-0">
                    {finding.severity}
                  </span>
                  <span className="truncate">{finding.title}</span>
                </div>
              ))}
              {diff.findings.removed.map((finding) => (
                <div key={finding.id} className="flex items-center space-x-1.5 text-critical">
                  <Minus className="w-3 h-3 shrink-0" />
                  <span className="uppercase text-[10px] font-semibold w-16 shrink-0">
                    {finding.severity}
                  </span>
                  <span className="truncate">{finding.title}</span>
                </div>
              ))}
              {diff.findings.counts.added === 0 && diff.findings.counts.removed === 0 && (
                <div className="text-muted">No finding changes</div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {listSection("Sections", diff.sections.added, diff.sections.removed)}
            {listSection("Signature rules", diff.signatures.added, diff.signatures.removed)}
            {listSection("Imports", diff.imports.added, diff.imports.removed)}
            {listSection("Exports", diff.exports.added, diff.exports.removed)}
          </div>

          <div className="p-3 rounded-card bg-panel border border-border space-y-2">
            <h3 className="text-xs font-semibold text-text uppercase tracking-wider">
              Metadata changed ({diff.metadata.changed.length})
            </h3>
            <div className="max-h-64 overflow-y-auto divide-y divide-border text-xs">
              {diff.metadata.changed.map((change) => (
                <div key={change.key} className="py-1.5 font-mono">
                  <div className="text-accent">{change.key}</div>
                  <div className="text-critical truncate">old: {JSON.stringify(change.old)}</div>
                  <div className="text-low truncate">new: {JSON.stringify(change.new)}</div>
                </div>
              ))}
              {diff.metadata.changed.length === 0 && (
                <div className="text-muted py-2">No metadata changes</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
