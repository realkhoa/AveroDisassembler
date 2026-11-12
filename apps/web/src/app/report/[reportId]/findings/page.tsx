"use client";

/**
 * @file page.tsx
 * @brief Findings browser route (/report/[reportId]/findings).
 */

import React, { useEffect, useState, use } from "react";
import { useSearchParams } from "next/navigation";
import { useReport } from "@/lib/report-context";
import { FindingsTable } from "@/components/findings/FindingsTable";
import type { AveroReport, Severity } from "@/types/report";

interface FindingsPageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Findings browser page component for filtering and exploring observations.
 * @param props Route props containing unresolved dynamic params.
 * @return React element representing the findings browser page.
 */
export default function FindingsPage({ params }: FindingsPageProps) {
  const resolvedParams = use(params);
  const searchParams = useSearchParams();
  const { activeReport, loadReportById } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);

  const initialSeverity = searchParams.get("severity") as Severity | null;
  const initialFindingId = searchParams.get("finding");

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
        <div className="text-xs text-muted">Loading findings...</div>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text">Security & Integrity Findings</h1>
        <p className="text-xs text-muted">
          All findings are ranked by severity and link directly to verifiable evidence locators.
        </p>
      </div>

      <FindingsTable
        reportId={report.artifact.id}
        findings={report.findings || []}
        initialSeverity={initialSeverity}
        initialFindingId={initialFindingId}
      />
    </div>
  );
}
