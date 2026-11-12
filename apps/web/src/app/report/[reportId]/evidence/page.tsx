"use client";

/**
 * @file page.tsx
 * @brief Evidence inspector route (/report/[reportId]/evidence).
 */

import React, { useEffect, useState, use } from "react";
import { useSearchParams } from "next/navigation";
import { useReport } from "@/lib/report-context";
import { EvidenceInspector } from "@/components/evidence/EvidenceInspector";
import type { AveroReport } from "@/types/report";

interface EvidencePageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Evidence inspector page component for inspecting verifiable evidence pointers.
 * @param props Route props containing unresolved dynamic params.
 * @return React element representing the evidence inspector page.
 */
export default function EvidencePage({ params }: EvidencePageProps) {
  const resolvedParams = use(params);
  const searchParams = useSearchParams();
  const { activeReport, loadReportById } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);

  const initialEvidenceId = searchParams.get("id");

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
        <div className="text-xs text-muted">Loading evidence items...</div>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text">Evidence Inspector</h1>
        <p className="text-xs text-muted">
          Inspect verifiable pointers, locator coordinates, and raw excerpts grounding the report observations.
        </p>
      </div>

      <EvidenceInspector
        reportId={report.artifact.id}
        evidenceList={report.artifact.evidence || []}
        findings={report.findings || []}
        initialEvidenceId={initialEvidenceId}
      />
    </div>
  );
}
