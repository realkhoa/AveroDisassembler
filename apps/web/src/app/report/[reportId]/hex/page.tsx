"use client";

/**
 * @file page.tsx
 * @brief Raw binary hex inspection route (/report/[reportId]/hex).
 */

import React, { useEffect, useState, use } from "react";
import { useSearchParams } from "next/navigation";
import { useReport } from "@/lib/report-context";
import { HexViewer } from "@/components/hex/HexViewer";
import type { AveroReport } from "@/types/report";

interface HexPageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Raw binary hex viewer page component.
 * @param props Route props containing unresolved dynamic params.
 * @return React element representing the hex viewer page.
 */
export default function HexPage({ params }: HexPageProps) {
  const resolvedParams = use(params);
  const searchParams = useSearchParams();
  const { activeReport, loadReportById } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);

  const initialOffsetStr = searchParams.get("offset");
  const initialOffset = initialOffsetStr ? parseInt(initialOffsetStr, 10) : 0;

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
        <div className="text-xs text-muted">Loading hex viewer...</div>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text">Hex Viewer</h1>
        <p className="text-xs text-muted">
          Paged raw binary byte inspection with 16-byte alignment, address gutters, and ASCII previews.
        </p>
      </div>

      <HexViewer reportId={report.artifact.id} initialOffset={initialOffset} />
    </div>
  );
}
