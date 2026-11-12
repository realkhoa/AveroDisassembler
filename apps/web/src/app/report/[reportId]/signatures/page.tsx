"use client";

/**
 * @file page.tsx
 * @brief Signature-rule matches route (/report/[reportId]/signatures).
 */

import React, { useEffect, useState, use } from "react";
import Link from "next/link";
import { FileSignature, AlertCircle, ShieldAlert } from "lucide-react";
import { useReport } from "@/lib/report-context";
import type { AveroReport } from "@/types/report";

interface SignaturesPageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Signature matches page: rule matches from the native YARA-subset engine.
 */
export default function SignaturesPage({ params }: SignaturesPageProps) {
  const resolvedParams = use(params);
  const { activeReport, loadReportById } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);

  useEffect(() => {
    if (!report || report.artifact.id !== resolvedParams.reportId) {
      loadReportById(resolvedParams.reportId).then((loaded) => {
        if (loaded) setReport(loaded);
      });
    }
  }, [resolvedParams.reportId, report, loadReportById]);

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-3">
        <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        <div className="text-xs text-muted">Loading signature matches…</div>
      </div>
    );
  }

  const facts = (report.facts?.["signatures.rules"] as Record<string, unknown>) || {};
  const matchedRules = (facts.matched_rules as string[]) || [];
  const signatureFindings = report.findings.filter(
    (finding) =>
      finding.category.toLowerCase().includes("signature") ||
      finding.title.toLowerCase().startsWith("signature:"),
  );

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text flex items-center space-x-2">
          <FileSignature className="w-5 h-5 text-accent" />
          <span>Signature Rules</span>
        </h1>
        <p className="text-xs text-muted">
          Matches from the embedded YARA-subset engine (<code className="font-mono">rules/avero-default.yar</code>).
        </p>
      </div>

      {matchedRules.length === 0 && signatureFindings.length === 0 ? (
        <div className="p-4 rounded-card bg-panel border border-border flex items-start space-x-2 text-xs text-muted">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <div className="text-text font-semibold">No signature rules matched</div>
            <p className="mt-0.5">
              The default ruleset did not trigger on this artifact. Coverage confirms the analyzer ran;
              see the Coverage screen for details.
            </p>
          </div>
        </div>
      ) : (
        <div className="rounded-card bg-panel border border-border overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-panel-2 text-muted uppercase tracking-wider text-[11px]">
              <tr>
                <th className="text-left px-4 py-2.5">Rule</th>
                <th className="text-left px-4 py-2.5">Severity</th>
                <th className="text-left px-4 py-2.5">Category</th>
                <th className="text-left px-4 py-2.5">Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {matchedRules.map((rule) => (
                <tr key={rule} className="hover:bg-panel-2/50">
                  <td className="px-4 py-2.5 font-mono text-text">{rule}</td>
                  <td className="px-4 py-2.5 text-muted">—</td>
                  <td className="px-4 py-2.5 text-muted">signature</td>
                  <td className="px-4 py-2.5 text-muted">see findings</td>
                </tr>
              ))}
              {signatureFindings.map((finding) => (
                <tr key={finding.id} className="hover:bg-panel-2/50">
                  <td className="px-4 py-2.5">
                    <Link
                      href={`/report/${report.artifact.id}/findings?finding=${finding.id}`}
                      className="text-accent hover:underline"
                    >
                      {finding.title}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="inline-flex items-center space-x-1 text-high">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span className="uppercase text-[10px] font-semibold">{finding.severity}</span>
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-muted">{finding.category}</td>
                  <td className="px-4 py-2.5 text-muted font-mono text-[10px]">
                    {finding.evidence_ids.join(", ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
