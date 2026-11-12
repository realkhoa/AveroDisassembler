"use client";

/**
 * @file SeverityBar.tsx
 * @brief Visual severity distribution bar linking directly to filtered findings.
 */

import React from "react";
import Link from "next/link";
import type { Finding, Severity } from "@/types/report";

interface SeverityBarProps {
  reportId: string;
  findings: Finding[];
}

/**
 * @brief Severity distribution bar component.
 */
export function SeverityBar({ reportId, findings }: SeverityBarProps) {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const f of findings) {
    if (f.severity in counts) {
      counts[f.severity]++;
    }
  }

  const total = findings.length;

  const severityOrder: Array<{ level: Severity; label: string; bgClass: string; textClass: string; borderClass: string }> = [
    { level: "critical", label: "Critical", bgClass: "bg-critical", textClass: "text-critical", borderClass: "border-critical/40" },
    { level: "high", label: "High", bgClass: "bg-high", textClass: "text-high", borderClass: "border-high/40" },
    { level: "medium", label: "Medium", bgClass: "bg-medium", textClass: "text-medium", borderClass: "border-medium/40" },
    { level: "low", label: "Low", bgClass: "bg-low", textClass: "text-low", borderClass: "border-low/40" },
    { level: "info", label: "Info", bgClass: "bg-info", textClass: "text-info", borderClass: "border-info/40" },
  ];

  return (
    <div className="p-4 rounded-card bg-panel border border-border space-y-3">
      <div className="flex items-center justify-between text-xs">
        <span className="font-semibold text-text uppercase tracking-wider text-[11px]">Findings by Severity</span>
        <span className="text-muted font-mono">{total} total</span>
      </div>

      {/* Progress segmented bar */}
      <div className="h-3 w-full rounded-chip bg-bg border border-border flex overflow-hidden">
        {total === 0 ? (
          <div className="w-full h-full bg-panel-2 text-center text-[10px] text-muted flex items-center justify-center">
            No findings
          </div>
        ) : (
          severityOrder.map((s) => {
            const count = counts[s.level];
            if (count === 0) return null;
            const pct = (count / total) * 100;
            return (
              <div
                key={s.level}
                style={{ width: `${pct}%` }}
                title={`${s.label}: ${count} (${pct.toFixed(0)}%)`}
                className={`${s.bgClass} h-full transition-all`}
              />
            );
          })
        )}
      </div>

      {/* Clickable severity chips */}
      <div className="flex flex-wrap items-center gap-2 pt-1">
        {severityOrder.map((s) => {
          const count = counts[s.level];
          return (
            <Link
              key={s.level}
              href={`/report/${reportId}/findings?severity=${s.level}`}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-chip text-xs border font-medium transition-all ${
                count > 0
                  ? `bg-panel-2 ${s.textClass} ${s.borderClass} hover:opacity-80`
                  : "bg-panel-2/50 text-muted/50 border-border cursor-default pointer-events-none"
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${count > 0 ? s.bgClass : "bg-muted/40"}`} />
              <span>{s.label}</span>
              <span className="font-bold font-mono">({count})</span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
