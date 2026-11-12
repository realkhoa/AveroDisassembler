"use client";

/**
 * @file page.tsx
 * @brief Extracted strings view route (/report/[reportId]/strings).
 */

import React, { useEffect, useState, use } from "react";
import { useReport } from "@/lib/report-context";
import { StringsViewer } from "@/components/strings/StringsViewer";
import type { AveroReport } from "@/types/report";

interface StringsPageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Extracted strings viewer page component.
 * @param props Route props containing unresolved dynamic params.
 * @return React element representing the strings page.
 */
export default function StringsPage({ params }: StringsPageProps) {
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
        <div className="text-xs text-muted">Loading strings...</div>
      </div>
    );
  }

  const strings = report.artifact.strings || [];

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text">Extracted Strings</h1>
        <p className="text-xs text-muted">
          Search, filter, and inspect bounded strings mapped to binary sections with offset locators.
        </p>
      </div>

      <StringsViewer reportId={report.artifact.id} strings={strings} />
    </div>
  );
}
