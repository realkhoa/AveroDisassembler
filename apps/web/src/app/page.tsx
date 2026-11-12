"use client";

/**
 * @file page.tsx
 * @brief Home landing page: file-mode report ingestion or API-mode artifact scanning.
 */

import React from "react";
import { ShieldCheck } from "lucide-react";
import { DropZone } from "@/components/home/DropZone";
import { ApiScanPanel } from "@/components/home/ApiScanPanel";
import { RecentReportsList } from "@/components/home/RecentReportsList";
import { useReport } from "@/lib/report-context";

/** @brief Home landing page component. */
export default function HomePage() {
  const { mode } = useReport();

  return (
    <div className="max-w-4xl mx-auto py-8 space-y-8">
      <div className="text-center space-y-2">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-chip bg-panel border border-border text-xs text-accent mb-2">
          <ShieldCheck className="w-4 h-4" />
          <span>Evidence-First Reverse Engineering Workbench</span>
        </div>
        <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-text">
          Avero Disassembler Workbench
        </h1>
        <p className="text-xs md:text-sm text-muted max-w-lg mx-auto">
          {mode === "API"
            ? "Upload an artifact to the local avero serve daemon and inspect the resulting report with live scan progress."
            : "Triage binaries at a glance, drill down from high-severity findings to exact bytes and locators, and explore structural metadata."}
        </p>
      </div>

      {mode === "API" ? <ApiScanPanel /> : <DropZone />}

      {mode === "FILE" && <RecentReportsList />}
    </div>
  );
}
