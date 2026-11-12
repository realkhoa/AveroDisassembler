"use client";

/**
 * @file TopFindingsList.tsx
 * @brief Displays high-priority findings on the triage dashboard.
 */

import React from "react";
import Link from "next/link";
import { AlertCircle, ChevronRight, ShieldAlert } from "lucide-react";
import type { Finding } from "@/types/report";

interface TopFindingsListProps {
  reportId: string;
  findings: Finding[];
}

/**
 * @brief Top findings preview list component.
 */
export function TopFindingsList({ reportId, findings }: TopFindingsListProps) {
  const severityWeight = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };

  const sorted = [...findings].sort((a, b) => {
    return (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0);
  });

  const top8 = sorted.slice(0, 8);

  if (top8.length === 0) {
    return (
      <div className="p-6 rounded-card bg-panel border border-border text-center text-xs text-muted">
        No findings reported for this artifact.
      </div>
    );
  }

  const severityBadgeColors = {
    critical: "bg-critical/20 text-critical border-critical/40",
    high: "bg-high/20 text-high border-high/40",
    medium: "bg-medium/20 text-medium border-medium/40",
    low: "bg-low/20 text-low border-low/40",
    info: "bg-info/20 text-info border-info/40",
  };

  return (
    <div className="rounded-card bg-panel border border-border p-4 space-y-3">
      <div className="flex items-center justify-between text-xs">
        <span className="font-semibold text-text uppercase tracking-wider text-[11px] flex items-center space-x-1.5">
          <ShieldAlert className="w-4 h-4 text-high" />
          <span>Top Findings</span>
        </span>
        <Link
          href={`/report/${reportId}/findings`}
          className="text-accent hover:underline text-xs flex items-center space-x-1"
        >
          <span>View all ({findings.length})</span>
          <ChevronRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      <div className="divide-y divide-border/60">
        {top8.map((f) => (
          <Link
            key={f.id}
            href={`/report/${reportId}/findings?finding=${f.id}`}
            className="py-2.5 flex items-start justify-between group hover:bg-panel-2/60 -mx-2 px-2 rounded-input transition-colors"
          >
            <div className="space-y-1 pr-3">
              <div className="flex items-center space-x-2">
                <span
                  className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-chip border ${
                    severityBadgeColors[f.severity]
                  }`}
                >
                  {f.severity}
                </span>
                <span className="text-xs font-semibold text-text group-hover:text-accent transition-colors">
                  {f.title}
                </span>
              </div>
              <p className="text-xs text-muted line-clamp-1">{f.detail}</p>
            </div>

            <div className="flex items-center space-x-2 shrink-0 pt-0.5">
              <span className="text-[11px] font-mono text-muted bg-bg px-1.5 py-0.5 rounded border border-border">
                {(f.confidence * 100).toFixed(0)}% conf
              </span>
              <ChevronRight className="w-4 h-4 text-muted group-hover:text-text" />
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
