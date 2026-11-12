"use client";

/**
 * @file StatusBar.tsx
 * @brief Bottom status bar with schema version, analyzer coverage, API mode and disclaimer.
 */

import React from "react";
import { Info, CheckCircle2, Wifi, WifiOff } from "lucide-react";
import { useReport } from "@/lib/report-context";

/** @brief Bottom status bar component. */
export function StatusBar() {
  const { activeReport, mode, apiHealth } = useReport();
  const coverage = activeReport?.coverage || {};
  const coverageCount = Object.keys(coverage).length;

  return (
    <footer className="h-7 border-t border-border bg-panel flex items-center justify-between px-3 text-[11px] text-muted select-none shrink-0 z-30">
      <div className="flex items-center space-x-3">
        <span className="font-mono text-muted">
          Contract: <span className="text-text">avero.report/v1</span>
        </span>

        {mode === "API" && (
          <span
            className={`flex items-center space-x-1 ${apiHealth ? "text-low" : "text-critical"}`}
          >
            {apiHealth ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
            <span>
              {apiHealth
                ? `${apiHealth.api_version} · core ${apiHealth.core_version}`
                : "API offline"}
            </span>
          </span>
        )}

        {coverageCount > 0 && (
          <span className="flex items-center space-x-1 text-low">
            <CheckCircle2 className="w-3 h-3" />
            <span>{coverageCount} analyzers completed</span>
          </span>
        )}
      </div>

      <div className="flex items-center space-x-1.5 text-muted">
        <Info className="w-3 h-3 text-accent" />
        <span>Static analysis only. The artifact is never executed.</span>
      </div>
    </footer>
  );
}
