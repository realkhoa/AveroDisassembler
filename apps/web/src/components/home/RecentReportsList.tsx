"use client";

/**
 * @file RecentReportsList.tsx
 * @brief Displays recently loaded reports from local storage for fast triage resumption.
 */

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Clock, ChevronRight, FileCode } from "lucide-react";
import { getDataSource } from "@/lib/data-source";
import type { ReportSummary } from "@/types/report";

/**
 * @brief Recent reports listing component.
 */
export function RecentReportsList() {
  const [reports, setReports] = useState<ReportSummary[]>([]);

  useEffect(() => {
    const fetchRecent = async () => {
      const dataSource = getDataSource();
      if (dataSource.listReports) {
        const list = await dataSource.listReports();
        setReports(list);
      }
    };
    fetchRecent();
  }, []);

  if (reports.length === 0) {
    return null;
  }

  return (
    <div className="w-full max-w-2xl mx-auto space-y-3">
      <div className="flex items-center space-x-2 text-xs font-semibold uppercase tracking-wider text-muted px-1">
        <Clock className="w-3.5 h-3.5" />
        <span>Recent Reports</span>
      </div>

      <div className="space-y-2">
        {reports.map((report) => (
          <Link
            key={report.id}
            href={`/report/${report.id}/overview`}
            className="flex items-center justify-between p-3 rounded-card bg-panel border border-border hover:border-accent/40 hover:bg-panel-2 transition-all group"
          >
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded bg-bg border border-border text-muted group-hover:text-accent transition-colors">
                <FileCode className="w-4 h-4" />
              </div>
              <div>
                <div className="text-xs font-semibold text-text group-hover:text-accent transition-colors">
                  {report.name}
                </div>
                <div className="text-[11px] text-muted font-mono">
                  sha256:{report.sha256.slice(0, 12)}… · {(report.size / 1024).toFixed(1)} KB
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              {/* Finding counts chips */}
              <div className="flex items-center space-x-1 text-[11px]">
                {report.findingsCount.high > 0 && (
                  <span className="px-1.5 py-0.5 rounded bg-high/20 text-high font-bold border border-high/30">
                    {report.findingsCount.high} high
                  </span>
                )}
                {report.findingsCount.medium > 0 && (
                  <span className="px-1.5 py-0.5 rounded bg-medium/20 text-medium font-bold border border-medium/30">
                    {report.findingsCount.medium} med
                  </span>
                )}
                <span className="text-muted px-1">
                  {report.findingsCount.total} findings
                </span>
              </div>

              <ChevronRight className="w-4 h-4 text-muted group-hover:text-text transition-colors" />
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
