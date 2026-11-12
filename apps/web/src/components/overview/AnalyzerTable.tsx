import React from "react";
import { CheckCircle2, AlertTriangle, HelpCircle } from "lucide-react";

/**
 * @file AnalyzerTable.tsx
 * @brief Table displaying analyzer execution coverage, unknowns, and warnings.
 */

interface AnalyzerTableProps {
  coverage?: Record<string, string>;
  unknowns?: string[];
  warnings?: string[];
}

/**
 * @brief Analyzer execution coverage summary component.
 */
export function AnalyzerTable({ coverage = {}, unknowns = [], warnings = [] }: AnalyzerTableProps) {
  const entries = Object.entries(coverage);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Analyzer status list */}
      <div className="p-4 rounded-card bg-panel border border-border space-y-3">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-text uppercase tracking-wider text-[11px]">
            Analyzers Coverage
          </span>
          <span className="text-muted text-[11px] font-mono">{entries.length} analyzers</span>
        </div>

        {entries.length === 0 ? (
          <div className="text-xs text-muted py-2">No analyzer coverage recorded.</div>
        ) : (
          <div className="divide-y divide-border/50 max-h-56 overflow-y-auto pr-1">
            {entries.map(([analyzer, status]) => (
              <div key={analyzer} className="py-2 flex items-center justify-between text-xs">
                <span className="font-mono text-text">{analyzer}</span>
                <span className="flex items-center space-x-1 text-low text-[11px] font-semibold bg-low/10 px-2 py-0.5 rounded border border-low/30">
                  <CheckCircle2 className="w-3 h-3" />
                  <span>{status}</span>
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Unknowns & Warnings */}
      <div className="p-4 rounded-card bg-panel border border-border space-y-3 flex flex-col justify-between">
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-text uppercase tracking-wider text-[11px]">
              Unknowns & Warnings
            </span>
            <span className="text-muted text-[11px] font-mono">
              {unknowns.length + warnings.length} items
            </span>
          </div>

          {unknowns.length === 0 && warnings.length === 0 ? (
            <div className="flex items-center space-x-2 text-xs text-low p-3 rounded-input bg-low/5 border border-low/20">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Clean scan: Zero warnings or unanalyzed structures.</span>
            </div>
          ) : (
            <div className="space-y-2 max-h-56 overflow-y-auto">
              {warnings.map((w, idx) => (
                <div
                  key={`warn-${idx}`}
                  className="p-2 rounded bg-medium/10 border border-medium/30 text-medium text-xs flex items-start space-x-2"
                >
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{w}</span>
                </div>
              ))}
              {unknowns.map((u, idx) => (
                <div
                  key={`unk-${idx}`}
                  className="p-2 rounded bg-info/10 border border-info/30 text-info text-xs flex items-start space-x-2"
                >
                  <HelpCircle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{u}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="text-[11px] text-muted border-t border-border pt-2">
          Avero reports surface coverage limits honestly without hiding unanalyzed sections.
        </div>
      </div>
    </div>
  );
}
