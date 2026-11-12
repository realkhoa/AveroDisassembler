"use client";

/**
 * @file page.tsx
 * @brief Binary sections & entropy inspection route (/report/[reportId]/sections).
 */

import React, { useEffect, useState, use } from "react";
import Link from "next/link";
import { Layers, Binary } from "lucide-react";
import { useReport } from "@/lib/report-context";
import { EntropyBar } from "@/components/sections/EntropyBar";
import type { AveroReport } from "@/types/report";

interface SectionsPageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Binary sections & entropy page component.
 * @param props Route props containing unresolved dynamic params.
 * @return React element representing the sections page.
 */
export default function SectionsPage({ params }: SectionsPageProps) {
  const resolvedParams = use(params);
  const { activeReport, loadReportById } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);

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
        <div className="text-xs text-muted">Loading sections...</div>
      </div>
    );
  }

  const sections = report.artifact.sections || [];

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text">Binary Sections</h1>
        <p className="text-xs text-muted">
          Inspect segment boundaries, memory layouts, access permissions, and Shannon entropy indicators.
        </p>
      </div>

      <div className="rounded-card bg-panel border border-border overflow-hidden">
        {sections.length === 0 ? (
          <div className="p-12 text-center text-xs text-muted space-y-2">
            <Layers className="w-8 h-8 text-muted/50 mx-auto" />
            <div>No sections found in this artifact format ({report.artifact.kinds.join(", ")}).</div>
            <p className="text-muted/80 max-w-sm mx-auto">
              Formats like APKs, JARs, or standalone scripts do not contain native PE/ELF header section tables.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-border bg-panel-2/80 text-muted uppercase tracking-wider text-[11px]">
                  <th className="py-2.5 px-4 font-semibold">Name</th>
                  <th className="py-2.5 px-4 font-semibold font-mono">Virtual Addr</th>
                  <th className="py-2.5 px-4 font-semibold font-mono">Virtual Size</th>
                  <th className="py-2.5 px-4 font-semibold font-mono">Raw Offset</th>
                  <th className="py-2.5 px-4 font-semibold font-mono">Raw Size</th>
                  <th className="py-2.5 px-4 font-semibold">Entropy (0-8)</th>
                  <th className="py-2.5 px-4 font-semibold">Flags</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {sections.map((sec, idx) => (
                  <tr key={`${sec.name}-${idx}`} className="hover:bg-panel-2/50 transition-colors">
                    <td className="py-3 px-4 font-mono font-bold text-accent">{sec.name}</td>
                    <td className="py-3 px-4 font-mono text-muted">
                      0x{sec.va.toString(16).toUpperCase()}
                    </td>
                    <td className="py-3 px-4 font-mono text-muted">
                      {(sec.vsize / 1024).toFixed(1)} KB
                    </td>
                    <td className="py-3 px-4 font-mono text-text">
                      0x{sec.raw_offset.toString(16).toUpperCase()}
                    </td>
                    <td className="py-3 px-4 font-mono text-text">
                      {(sec.raw_size / 1024).toFixed(1)} KB
                    </td>
                    <td className="py-3 px-4">
                      <EntropyBar entropy={sec.entropy} />
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {sec.flags.map((fl) => (
                          <span
                            key={fl}
                            className="text-[10px] px-1.5 py-0.2 rounded bg-bg text-muted border border-border font-mono"
                          >
                            {fl}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <Link
                        href={`/report/${report.artifact.id}/hex?offset=${sec.raw_offset}`}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-input bg-panel-2 hover:bg-border text-xs text-muted hover:text-text border border-border transition-colors"
                      >
                        <Binary className="w-3.5 h-3.5" />
                        <span>View Hex</span>
                      </Link>
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
