"use client";

/**
 * @file page.tsx
 * @brief Overview triage dashboard route (/report/[reportId]/overview).
 */

import React, { useEffect, useState, use } from "react";
import { useRouter } from "next/navigation";
import {
  Copy,
  Check,
  FileCode,
  Shield,
  Layers,
  FolderTree,
  Binary,
  Cpu,
  FileSearch,
  AlertTriangle,
} from "lucide-react";
import { useReport } from "@/lib/report-context";
import { StatCard } from "@/components/overview/StatCard";
import { SeverityBar } from "@/components/overview/SeverityBar";
import { TopFindingsList } from "@/components/overview/TopFindingsList";
import { AnalyzerTable } from "@/components/overview/AnalyzerTable";
import type { AveroReport } from "@/types/report";

interface OverviewPageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Overview triage dashboard page component.
 * @param props Route props containing unresolved dynamic params.
 * @return React element representing the triage overview page.
 */
export default function OverviewPage({ params }: OverviewPageProps) {
  const resolvedParams = use(params);
  const router = useRouter();
  const { activeReport, loadReportById } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);
  const [copiedSha, setCopiedSha] = useState(false);

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
        <div className="text-xs text-muted">Loading artifact triage report...</div>
      </div>
    );
  }

  const { artifact, findings = [], coverage = {}, unknowns = [], warnings = [] } = report;
  const fileName = artifact.path.split(/[/\\]/).pop() || artifact.id;
  const sha256 = artifact.hashes?.sha256 || "";

  const handleCopySha = async () => {
    if (sha256) {
      await navigator.clipboard.writeText(sha256);
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    }
  };

  // Extract optional APK facts if present
  const apkFacts = (report.facts?.["apk.structure"] as Record<string, unknown>) || null;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="p-5 rounded-card bg-panel border border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-semibold px-2 py-0.5 rounded-chip bg-accent/10 text-accent border border-accent/30 uppercase">
              {artifact.kinds.join(" / ") || "unknown"}
            </span>
            <h1 className="text-xl font-bold text-text flex items-center space-x-2">
              <FileCode className="w-5 h-5 text-accent" />
              <span>{fileName}</span>
            </h1>
          </div>

          <div className="flex items-center space-x-2 text-xs text-muted font-mono pt-1">
            <span>SHA-256: {sha256}</span>
            <button
              onClick={handleCopySha}
              title="Copy full SHA-256 hash"
              className="p-1 rounded hover:bg-panel-2 text-muted hover:text-text border border-transparent hover:border-border transition-colors"
            >
              {copiedSha ? <Check className="w-3.5 h-3.5 text-low" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs">
          <div className="p-3 rounded-card bg-bg border border-border text-center min-w-24">
            <div className="text-[11px] text-muted">Entropy</div>
            <div className="text-base font-bold font-mono text-text">
              {artifact.entropy ? artifact.entropy.toFixed(3) : "N/A"}
            </div>
          </div>
          <div className="p-3 rounded-card bg-bg border border-border text-center min-w-24">
            <div className="text-[11px] text-muted">File Size</div>
            <div className="text-base font-bold font-mono text-text">
              {(artifact.size / 1024).toFixed(1)} KB
            </div>
          </div>
        </div>
      </div>

      {/* APK Risk Banner (if debuggable or exported components without permission) */}
      {apkFacts && apkFacts.apk_debuggable === true && (
        <div className="p-4 rounded-card bg-critical/10 border border-critical/40 flex items-start space-x-3 text-critical">
          <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs">
            <div className="font-bold">High Risk: APK debuggable is set to true</div>
            <p className="text-text/90">
              The manifest enables <code className="bg-bg px-1 py-0.5 rounded border border-critical/30 font-mono">android:debuggable=&quot;true&quot;</code>.
              This allows unauthorized debuggers to attach to runtime memory and extract secrets.
            </p>
          </div>
        </div>
      )}

      {/* Stat Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 md:gap-4">
        <StatCard
          label="Findings"
          value={findings.length}
          subValue="Severity ranked"
          icon={<Shield className="w-4 h-4 text-high" />}
          href={`/report/${artifact.id}/findings`}
        />
        <StatCard
          label="Evidence Items"
          value={artifact.evidence?.length || 0}
          subValue="Verifiable pointers"
          icon={<FileSearch className="w-4 h-4 text-accent" />}
          href={`/report/${artifact.id}/evidence`}
        />
        <StatCard
          label="Sections"
          value={artifact.sections?.length || 0}
          subValue="Binary layout"
          icon={<Layers className="w-4 h-4 text-muted" />}
          href={`/report/${artifact.id}/sections`}
        />
        <StatCard
          label="Strings"
          value={artifact.strings?.length || 0}
          subValue="Extracted text"
          icon={<Binary className="w-4 h-4 text-muted" />}
          href={`/report/${artifact.id}/strings`}
        />
      </div>

      {/* Severity Breakdown Bar */}
      <SeverityBar reportId={artifact.id} findings={findings} />

      {/* Top Findings */}
      <TopFindingsList reportId={artifact.id} findings={findings} />

      {/* APK Specific Information Card (if applicable) */}
      {apkFacts && (
        <div className="p-4 rounded-card bg-panel border border-border space-y-3">
          <div className="text-xs font-semibold text-text uppercase tracking-wider text-[11px]">
            APK Manifest Facts
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div>
              <span className="text-muted block text-[11px]">Package</span>
              <span className="font-mono font-bold text-text">{String(apkFacts.apk_package || "N/A")}</span>
            </div>
            <div>
              <span className="text-muted block text-[11px]">Version</span>
              <span className="font-mono text-text">
                {String(apkFacts.apk_version_name || "N/A")} ({String(apkFacts.apk_version_code || "")})
              </span>
            </div>
            <div>
              <span className="text-muted block text-[11px]">SDK Range</span>
              <span className="font-mono text-text">
                Min: {String(apkFacts.apk_min_sdk || "N/A")} · Target: {String(apkFacts.apk_target_sdk || "N/A")}
              </span>
            </div>
            <div>
              <span className="text-muted block text-[11px]">Dangerous Permissions</span>
              <span className="font-bold text-high">
                {Array.isArray(apkFacts.apk_dangerous_permissions) ? apkFacts.apk_dangerous_permissions.length : 0} permissions
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Coverage & Diagnostics */}
      <AnalyzerTable coverage={coverage} unknowns={unknowns} warnings={warnings} />
    </div>
  );
}
