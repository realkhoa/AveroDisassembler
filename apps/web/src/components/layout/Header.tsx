"use client";

/**
 * @file Header.tsx
 * @brief Top navigation header with active report metadata, adapter mode and API status.
 */

import React from "react";
import Link from "next/link";
import { ShieldCheck, Settings, FileCode, Search, Package } from "lucide-react";
import { useReport } from "@/lib/report-context";

/** @brief Application header component. */
export function Header() {
  const { activeReport, mode, apiHealth, apiError } = useReport();
  const reportName =
    activeReport?.artifact?.path?.split(/[/\\]/).pop() || activeReport?.artifact?.id?.slice(0, 16);
  const sha256Short = activeReport?.artifact?.hashes?.sha256?.slice(0, 8);

  return (
    <header className="h-14 border-b border-border bg-panel flex items-center justify-between px-4 select-none shrink-0 z-30">
      <div className="flex items-center space-x-3">
        <Link href="/" className="flex items-center space-x-2 text-accent font-bold text-base hover:opacity-90">
          <ShieldCheck className="w-5 h-5" />
          <span className="tracking-wide">Avero</span>
          <span className="text-xs px-1.5 py-0.5 rounded bg-panel-2 text-muted border border-border">Disassembler</span>
        </Link>

        {activeReport && (
          <div className="hidden md:flex items-center space-x-2 ml-4 pl-4 border-l border-border text-xs">
            <span className="text-muted flex items-center space-x-1">
              <FileCode className="w-3.5 h-3.5" />
              <span className="font-medium text-text">{reportName}</span>
            </span>
            {sha256Short && (
              <span className="font-mono text-muted bg-panel-2 px-1.5 py-0.5 rounded border border-border">
                sha256:{sha256Short}…
              </span>
            )}
          </div>
        )}
      </div>

      <div className="flex items-center space-x-3">
        {mode === "API" && (
          <span
            className={`hidden sm:flex items-center space-x-1.5 text-[11px] px-2 py-1 rounded-chip border ${
              apiHealth
                ? "bg-low/10 text-low border-low/40"
                : "bg-critical/10 text-critical border-critical/40"
            }`}
            title={apiError || (apiHealth ? `core ${apiHealth.core_version} · ${apiHealth.api_version}` : "API offline")}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${apiHealth ? "bg-low" : "bg-critical"}`}
            />
            <span>{apiHealth ? "API READY" : "API OFFLINE"}</span>
          </span>
        )}

        <span className="text-xs px-2.5 py-1 rounded-chip font-semibold tracking-wider bg-panel-2 text-accent border border-accent/40">
          {mode} MODE
        </span>

        <div className="relative hidden lg:block">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-muted pointer-events-none" />
          <input
            type="text"
            placeholder="Search report (Press /)..."
            aria-label="Global report search"
            className="bg-bg border border-border text-xs rounded-input pl-8 pr-3 py-1.5 w-56 text-text focus:border-accent focus:outline-none transition-colors"
          />
        </div>

        <Link
          href="/engines"
          title="Engines"
          className="p-1.5 rounded-input hover:bg-panel-2 text-muted hover:text-text border border-transparent hover:border-border transition-colors"
        >
          <Package className="w-4 h-4" />
        </Link>

        <Link
          href="/settings"
          title="Settings"
          className="p-1.5 rounded-input hover:bg-panel-2 text-muted hover:text-text border border-transparent hover:border-border transition-colors"
        >
          <Settings className="w-4 h-4" />
        </Link>
      </div>
    </header>
  );
}
