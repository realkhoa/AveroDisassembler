"use client";

/**
 * @file page.tsx
 * @brief Artifact metadata explorer route (/report/[reportId]/metadata).
 */

import React, { useEffect, useState, useMemo, use } from "react";
import { Database, Search, Copy, Check } from "lucide-react";
import { useReport } from "@/lib/report-context";
import type { AveroReport } from "@/types/report";

interface MetadataPageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Metadata explorer page component for inspecting key/value artifact facts.
 * @param props Route props containing unresolved dynamic params.
 * @return React element representing the metadata page.
 */
export default function MetadataPage({ params }: MetadataPageProps) {
  const resolvedParams = use(params);
  const { activeReport, loadReportById } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);
  const [searchQuery, setSearchQuery] = useState("");
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

  const metadata = report?.artifact?.metadata || {};

  const filteredEntries = useMemo(() => {
    const entries = Object.entries(metadata);
    if (!searchQuery.trim()) return entries;
    const q = searchQuery.toLowerCase();
    return entries.filter(
      ([key, val]) =>
        key.toLowerCase().includes(q) ||
        JSON.stringify(val).toLowerCase().includes(q)
    );
  }, [metadata, searchQuery]);

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-3">
        <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        <div className="text-xs text-muted">Loading artifact metadata...</div>
      </div>
    );
  }

  const handleCopyJson = async () => {
    await navigator.clipboard.writeText(JSON.stringify(metadata, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-text">Artifact Metadata</h1>
          <p className="text-xs text-muted">
            Searchable key-value properties extracted by format probes and container analyzers.
          </p>
        </div>

        <button
          onClick={handleCopyJson}
          className="px-3 py-1.5 rounded-input bg-panel border border-border hover:bg-panel-2 text-xs text-text flex items-center space-x-1.5 transition-colors self-start sm:self-auto"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-low" /> : <Copy className="w-3.5 h-3.5" />}
          <span>Copy Metadata JSON</span>
        </button>
      </div>

      {/* Search Toolbar */}
      <div className="p-3.5 rounded-card bg-panel border border-border flex items-center justify-between">
        <div className="relative w-full max-w-sm">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-muted pointer-events-none" />
          <input
            type="text"
            placeholder="Search metadata keys or values..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-bg border border-border text-xs rounded-input pl-8 pr-3 py-1.5 w-full text-text focus:border-accent focus:outline-none"
          />
        </div>
        <div className="text-[11px] text-muted font-mono">
          {filteredEntries.length} of {Object.keys(metadata).length} properties
        </div>
      </div>

      {/* Metadata Table */}
      <div className="rounded-card bg-panel border border-border overflow-hidden">
        {filteredEntries.length === 0 ? (
          <div className="p-12 text-center text-xs text-muted">
            <Database className="w-8 h-8 text-muted/50 mx-auto mb-2" />
            <div>No metadata properties found.</div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-border bg-panel-2/80 text-muted uppercase tracking-wider text-[11px]">
                  <th className="py-2.5 px-4 font-semibold w-1/3">Property Key</th>
                  <th className="py-2.5 px-4 font-semibold">Value</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {filteredEntries.map(([key, val], idx) => (
                  <tr key={key} className={idx % 2 === 0 ? "bg-panel/50" : "bg-bg"}>
                    <td className="py-2.5 px-4 font-mono font-semibold text-accent select-none align-top">
                      {key}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-text break-all align-top">
                      {typeof val === "object" && val !== null ? (
                        <pre className="text-[11px] bg-panel p-2 rounded border border-border overflow-x-auto">
                          {JSON.stringify(val, null, 2)}
                        </pre>
                      ) : (
                        String(val)
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
