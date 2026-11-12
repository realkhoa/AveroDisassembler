"use client";

/**
 * @file page.tsx
 * @brief Analysis coverage, unknowns, and warnings route (/report/[reportId]/coverage).
 */

import React, { useEffect, useState, use } from "react";
import { Activity, CheckCircle2, AlertTriangle, HelpCircle, Copy, Check } from "lucide-react";
import { useReport } from "@/lib/report-context";
import type { AveroReport } from "@/types/report";

interface CoveragePageProps {
  params: Promise<{ reportId: string }>;
}

export default function CoveragePage({ params }: CoveragePageProps) {
  const resolvedParams = use(params);
  const { activeReport, loadReportById } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!report || report.artifact.id !== resolvedParams.reportId) {
      loadReportById(resolvedParams.reportId).then((loaded) => {
        if (loaded) {
          setReport(loaded);
        }
      });
    }
  }, [resolvedParams.reportId, report, loadReportById]);

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-3">
        <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        <div className="text-xs text-muted">Loading coverage report...</div>
      </div>
    );
  }

  const coverage = report.coverage || {};
  const unknowns = report.unknowns || [];
  const warnings = report.warnings || [];

  const handleCopyDiagnostics = async () => {
    const summary = {
      coverage,
      unknowns,
      warnings,
    };
    await navigator.clipboard.writeText(JSON.stringify(summary, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-text">Coverage & Unknowns</h1>
          <p className="text-xs text-muted">
            Transparently audits analyzer execution states, runtime warnings, and unparsed boundaries.
          </p>
        </div>

        <button
          onClick={handleCopyDiagnostics}
          className="px-3 py-1.5 rounded-input bg-panel border border-border hover:bg-panel-2 text-xs text-text flex items-center space-x-1.5 transition-colors self-start sm:self-auto"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-low" /> : <Copy className="w-3.5 h-3.5" />}
          <span>Copy Diagnostics</span>
        </button>
      </div>

      {/* Analyzer Coverage Table */}
      <div className="rounded-card bg-panel border border-border overflow-hidden">
        <div className="p-3 border-b border-border bg-panel-2/60 flex items-center justify-between text-xs font-semibold text-text">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-accent" />
            <span>Analyzer Pipeline Status</span>
          </div>
          <span className="font-mono text-muted text-[11px]">
            {Object.keys(coverage).length} analyzers executed
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-border bg-panel-2/40 text-muted uppercase tracking-wider text-[11px]">
                <th className="py-2.5 px-4 font-semibold">Analyzer ID</th>
                <th className="py-2.5 px-4 font-semibold">Execution Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {Object.entries(coverage).map(([analyzer, status]) => (
                <tr key={analyzer} className="hover:bg-panel-2/40">
                  <td className="py-2.5 px-4 font-mono font-medium text-text">{analyzer}</td>
                  <td className="py-2.5 px-4">
                    <span className="inline-flex items-center space-x-1 text-low text-[11px] font-semibold bg-low/10 px-2 py-0.5 rounded border border-low/30">
                      <CheckCircle2 className="w-3 h-3" />
                      <span>{status}</span>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Unknowns & Warnings Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Warnings */}
        <div className="p-4 rounded-card bg-panel border border-border space-y-3">
          <div className="flex items-center space-x-2 text-xs font-semibold text-medium uppercase tracking-wider text-[11px]">
            <AlertTriangle className="w-4 h-4" />
            <span>Analyzer Warnings ({warnings.length})</span>
          </div>

          {warnings.length === 0 ? (
            <div className="text-xs text-muted p-4 bg-bg rounded-input text-center">
              No analyzer warnings reported.
            </div>
          ) : (
            <div className="space-y-2">
              {warnings.map((w, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded bg-medium/10 border border-medium/30 text-medium text-xs leading-relaxed"
                >
                  {w}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Unknowns */}
        <div className="p-4 rounded-card bg-panel border border-border space-y-3">
          <div className="flex items-center space-x-2 text-xs font-semibold text-info uppercase tracking-wider text-[11px]">
            <HelpCircle className="w-4 h-4" />
            <span>Unanalyzed / Unknown Structures ({unknowns.length})</span>
          </div>

          {unknowns.length === 0 ? (
            <div className="text-xs text-muted p-4 bg-bg rounded-input text-center">
              All detected structures were parsed cleanly.
            </div>
          ) : (
            <div className="space-y-2">
              {unknowns.map((u, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded bg-info/10 border border-info/30 text-info text-xs leading-relaxed"
                >
                  {u}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
