"use client";

/**
 * @file page.tsx
 * @brief Imports & Exports route (/report/[reportId]/imports).
 */

import React, { useEffect, useState, useMemo, use } from "react";
import { FolderTree, Search, ChevronDown, ChevronRight, FileOutput, Library } from "lucide-react";
import { useReport } from "@/lib/report-context";
import type { AveroReport, ImportEntry, ExportEntry } from "@/types/report";

interface ImportsPageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Dynamic imports and exports viewer page component.
 * @param props Route props containing unresolved dynamic params.
 * @return React element representing the imports and exports page.
 */
export default function ImportsPage({ params }: ImportsPageProps) {
  const resolvedParams = use(params);
  const { activeReport, loadReportById } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);
  const [searchQuery, setSearchQuery] = useState("");
  const [collapsedLibs, setCollapsedLibs] = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab] = useState<"imports" | "exports">("imports");

  useEffect(() => {
    if (!report || report.artifact.id !== resolvedParams.reportId) {
      loadReportById(resolvedParams.reportId).then((loaded) => {
        if (loaded) {
          setReport(loaded);
        }
      });
    }
  }, [resolvedParams.reportId, report, loadReportById]);

  const imports = report?.artifact?.imports || [];
  const exports = report?.artifact?.exports || [];

  // Group imports by library name
  const groupedImports = useMemo(() => {
    const map = new Map<string, ImportEntry[]>();
    for (const imp of imports) {
      const lib = imp.library || "Unknown";
      const list = map.get(lib) || [];
      list.push(imp);
      map.set(lib, list);
    }
    return map;
  }, [imports]);

  // Filter imports by query
  const filteredGroupedImports = useMemo(() => {
    if (!searchQuery.trim()) return groupedImports;
    const q = searchQuery.toLowerCase();
    const result = new Map<string, ImportEntry[]>();

    for (const [lib, list] of groupedImports.entries()) {
      const libMatches = lib.toLowerCase().includes(q);
      const matchedEntries = list.filter(
        (e) => (e.name && e.name.toLowerCase().includes(q)) || libMatches
      );
      if (matchedEntries.length > 0) {
        result.set(lib, matchedEntries);
      }
    }
    return result;
  }, [groupedImports, searchQuery]);

  // Filter exports by query
  const filteredExports = useMemo(() => {
    if (!searchQuery.trim()) return exports;
    const q = searchQuery.toLowerCase();
    return exports.filter(
      (e) =>
        (e.name && e.name.toLowerCase().includes(q)) ||
        (e.forwarder && e.forwarder.toLowerCase().includes(q))
    );
  }, [exports, searchQuery]);

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-3">
        <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        <div className="text-xs text-muted">Loading imports and exports...</div>
      </div>
    );
  }

  const toggleLibrary = (lib: string) => {
    setCollapsedLibs((prev) => {
      const next = new Set(prev);
      if (next.has(lib)) next.delete(lib);
      else next.add(lib);
      return next;
    });
  };

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-text">Imports & Exports</h1>
          <p className="text-xs text-muted">
            Inspect external dynamic link library dependencies and public binary export tables.
          </p>
        </div>

        {/* Tab switch */}
        <div className="flex items-center space-x-1 p-1 rounded-card bg-panel border border-border">
          <button
            onClick={() => setActiveTab("imports")}
            className={`px-3 py-1.5 rounded-input text-xs font-semibold transition-colors flex items-center space-x-1.5 ${
              activeTab === "imports"
                ? "bg-accent/20 text-accent border border-accent/30"
                : "text-muted hover:text-text"
            }`}
          >
            <FolderTree className="w-3.5 h-3.5" />
            <span>Imports ({imports.length})</span>
          </button>
          <button
            onClick={() => setActiveTab("exports")}
            className={`px-3 py-1.5 rounded-input text-xs font-semibold transition-colors flex items-center space-x-1.5 ${
              activeTab === "exports"
                ? "bg-accent/20 text-accent border border-accent/30"
                : "text-muted hover:text-text"
            }`}
          >
            <FileOutput className="w-3.5 h-3.5" />
            <span>Exports ({exports.length})</span>
          </button>
        </div>
      </div>

      {/* Search Toolbar */}
      <div className="p-3.5 rounded-card bg-panel border border-border flex items-center justify-between">
        <div className="relative w-full max-w-sm">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-muted pointer-events-none" />
          <input
            type="text"
            placeholder={
              activeTab === "imports"
                ? "Search library or imported symbol..."
                : "Search exported function..."
            }
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-bg border border-border text-xs rounded-input pl-8 pr-3 py-1.5 w-full text-text focus:border-accent focus:outline-none"
          />
        </div>
        <div className="text-[11px] text-muted font-mono">
          {activeTab === "imports"
            ? `${filteredGroupedImports.size} libraries`
            : `${filteredExports.length} exported symbols`}
        </div>
      </div>

      {/* Main Content Area */}
      {activeTab === "imports" ? (
        <div className="space-y-3">
          {filteredGroupedImports.size === 0 ? (
            <div className="p-12 text-center text-xs text-muted rounded-card bg-panel border border-border">
              <Library className="w-8 h-8 text-muted/50 mx-auto mb-2" />
              <div>No imported libraries recorded in this artifact.</div>
            </div>
          ) : (
            Array.from(filteredGroupedImports.entries()).map(([lib, list]) => {
              const isCollapsed = collapsedLibs.has(lib);
              return (
                <div key={lib} className="rounded-card bg-panel border border-border overflow-hidden">
                  <button
                    onClick={() => toggleLibrary(lib)}
                    className="w-full p-3 bg-panel-2/60 hover:bg-panel-2 flex items-center justify-between text-xs font-semibold text-text transition-colors"
                  >
                    <div className="flex items-center space-x-2">
                      {isCollapsed ? <ChevronRight className="w-4 h-4 text-muted" /> : <ChevronDown className="w-4 h-4 text-accent" />}
                      <span className="font-mono text-accent">{lib}</span>
                    </div>
                    <span className="text-[11px] font-mono text-muted bg-bg px-2 py-0.5 rounded border border-border">
                      {list.length} functions
                    </span>
                  </button>

                  {!isCollapsed && (
                    <div className="divide-y divide-border/40 p-2 bg-bg/50">
                      {list.map((imp, idx) => (
                        <div
                          key={`${imp.name}-${idx}`}
                          className="py-1.5 px-3 flex items-center justify-between text-xs hover:bg-panel-2/40 rounded transition-colors"
                        >
                          <span className="font-mono text-text">
                            {imp.name || (imp.ordinal !== undefined ? `Ordinal ${imp.ordinal}` : "Unknown")}
                          </span>
                          {imp.iat_rva !== undefined && (
                            <span className="font-mono text-[11px] text-muted">
                              IAT: 0x{imp.iat_rva.toString(16).toUpperCase()}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      ) : (
        <div className="rounded-card bg-panel border border-border overflow-hidden">
          {filteredExports.length === 0 ? (
            <div className="p-12 text-center text-xs text-muted">
              <FileOutput className="w-8 h-8 text-muted/50 mx-auto mb-2" />
              <div>No exported symbols found.</div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-border bg-panel-2/80 text-muted uppercase tracking-wider text-[11px]">
                    <th className="py-2.5 px-4 font-semibold">Name</th>
                    <th className="py-2.5 px-4 font-semibold font-mono w-24">Ordinal</th>
                    <th className="py-2.5 px-4 font-semibold font-mono w-32">RVA</th>
                    <th className="py-2.5 px-4 font-semibold">Forwarder</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {filteredExports.map((exp, idx) => (
                    <tr key={`${exp.name}-${idx}`} className="hover:bg-panel-2/50 transition-colors">
                      <td className="py-2.5 px-4 font-mono font-bold text-accent">
                        {exp.name || "(anonymous)"}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-muted">{exp.ordinal}</td>
                      <td className="py-2.5 px-4 font-mono text-text">
                        0x{exp.rva.toString(16).toUpperCase()}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-muted">
                        {exp.forwarder || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
