"use client";

/**
 * @file layout.tsx
 * @brief Report route guard: resolves the requested report and shows a friendly error
 *        instead of an infinite spinner when it is not available (deep links, API offline).
 */

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { AlertTriangle, Home } from "lucide-react";
import { useReport } from "@/lib/report-context";

/**
 * @brief Layout wrapping all `/report/[reportId]/*` screens.
 */
export default function ReportLayout({ children }: { children: React.ReactNode }) {
  const params = useParams<{ reportId: string }>();
  const reportId = params.reportId;
  const { activeReport, loadReportById } = useReport();
  const [status, setStatus] = useState<"loading" | "ready" | "missing">("loading");

  useEffect(() => {
    if (activeReport?.artifact.id === reportId) {
      setStatus("ready");
      return;
    }
    let cancelled = false;
    setStatus("loading");
    loadReportById(reportId).then((report) => {
      if (!cancelled) setStatus(report ? "ready" : "missing");
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reportId, activeReport?.artifact.id]);

  if (status === "missing") {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] space-y-4 text-center">
        <div className="w-12 h-12 rounded-full bg-critical/10 border border-critical/30 flex items-center justify-center">
          <AlertTriangle className="w-6 h-6 text-critical" />
        </div>
        <div className="space-y-1">
          <h1 className="text-base font-semibold text-text">Report not available</h1>
          <p className="text-xs text-muted max-w-md">
            This report is not loaded in the current adapter. In file mode, open its
            <code className="mx-1 text-accent">report.json</code> from Home; in API mode, make sure
            <code className="mx-1 text-accent">avero serve</code> is running and the artifact was scanned.
          </p>
          <p className="text-[11px] text-muted font-mono break-all">{reportId}</p>
        </div>
        <Link
          href="/"
          className="px-3 py-1.5 rounded-input bg-accent/10 hover:bg-accent/20 text-accent text-xs font-semibold border border-accent/30 flex items-center space-x-1.5"
        >
          <Home className="w-3.5 h-3.5" />
          <span>Back to Home</span>
        </Link>
      </div>
    );
  }

  if (status === "loading") {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-3">
        <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        <div className="text-xs text-muted">Loading report…</div>
      </div>
    );
  }

  return <>{children}</>;
}
