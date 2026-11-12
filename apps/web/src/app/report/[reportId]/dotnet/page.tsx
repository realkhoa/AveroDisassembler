"use client";

/**
 * @file page.tsx
 * @brief .NET metadata facts route (/report/[reportId]/dotnet).
 */

import React, { useEffect, useState, use } from "react";
import { Cpu, Boxes, FunctionSquare, Layers, AlertCircle } from "lucide-react";
import { useReport } from "@/lib/report-context";
import type { AveroReport } from "@/types/report";

interface DotnetPageProps {
  params: Promise<{ reportId: string }>;
}

interface ObfuscationFacts {
  non_ascii_ratio?: number;
  non_ascii_type_names?: number;
  sampled_types?: number;
  short_ratio?: number;
  short_type_names?: number;
}

/**
 * @brief .NET metadata page: runtime, module, counts, type sample and obfuscation.
 */
export default function DotnetPage({ params }: DotnetPageProps) {
  const resolvedParams = use(params);
  const { activeReport, loadReportById, source } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);
  const [apiFacts, setApiFacts] = useState<Record<string, unknown> | null>(null);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    if (!report || report.artifact.id !== resolvedParams.reportId) {
      loadReportById(resolvedParams.reportId).then((loaded) => {
        if (loaded) setReport(loaded);
      });
    }
  }, [resolvedParams.reportId, report, loadReportById]);

  useEffect(() => {
    if (report && !report.facts?.["dotnet.metadata"] && source.getDotnet) {
      source
        .getDotnet(report.artifact.id)
        .then((facts) => setApiFacts(facts))
        .catch(() => setApiFacts(null));
    }
  }, [report, source]);

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-3">
        <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        <div className="text-xs text-muted">Loading .NET metadata…</div>
      </div>
    );
  }

  const facts = ((report.facts?.["dotnet.metadata"] as Record<string, unknown>) ||
    apiFacts ||
    {}) as Record<string, unknown>;
  const typeNames = ((facts.type_names_sample as string[]) || []).filter((name) =>
    name.toLowerCase().includes(filter.toLowerCase()),
  );
  const obfuscation = (facts.obfuscation as ObfuscationFacts) || {};

  const cards: { label: string; value: string | number; icon: React.ComponentType<{ className?: string }> }[] = [
    { label: "Runtime", value: String(facts.runtime_version || "n/a"), icon: Cpu },
    { label: "CLR", value: String(facts.clr_runtime_version || "n/a"), icon: Layers },
    { label: "Types", value: Number(facts.type_count || 0), icon: Boxes },
    { label: "Methods", value: Number(facts.method_count || 0), icon: FunctionSquare },
    { label: "Fields", value: Number(facts.field_count || 0), icon: Layers },
    { label: "Module", value: String(facts.module_name || report.artifact.path.split(/[/\\]/).pop() || "n/a"), icon: Cpu },
  ];

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text flex items-center space-x-2">
          <Cpu className="w-5 h-5 text-accent" />
          <span>.NET Metadata</span>
        </h1>
        <p className="text-xs text-muted">
          CLR metadata parsed in pure Rust: runtime, module, type/method counts, type names and obfuscation heuristics.
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <div key={card.label} className="p-3 rounded-card bg-panel border border-border">
              <div className="flex items-center space-x-1.5 text-[11px] text-muted uppercase tracking-wider">
                <Icon className="w-3.5 h-3.5" />
                <span>{card.label}</span>
              </div>
              <div className="mt-1 text-sm font-semibold text-text font-mono break-all">{card.value}</div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 p-4 rounded-card bg-panel border border-border space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-text">Type names (sample)</h2>
            <input
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              placeholder="Filter types…"
              className="bg-bg border border-border text-xs rounded-input px-2.5 py-1.5 text-text focus:border-accent focus:outline-none"
            />
          </div>
          <div className="max-h-80 overflow-y-auto divide-y divide-border rounded-input border border-border">
            {typeNames.map((name) => (
              <div key={name} className="px-3 py-1.5 text-xs font-mono text-text hover:bg-panel-2">
                {name}
              </div>
            ))}
            {typeNames.length === 0 && (
              <div className="px-3 py-4 text-xs text-muted">No type names available.</div>
            )}
          </div>
        </div>

        <div className="p-4 rounded-card bg-panel border border-border space-y-3">
          <h2 className="text-sm font-semibold text-text">Obfuscation heuristics</h2>
          {Object.keys(obfuscation).length === 0 ? (
            <p className="text-xs text-muted">No obfuscation metrics reported.</p>
          ) : (
            <div className="space-y-2 text-xs">
              {[
                ["Non-ASCII type names", obfuscation.non_ascii_type_names],
                ["Sampled types", obfuscation.sampled_types],
                ["Short type names", obfuscation.short_type_names],
              ].map(([label, value]) => (
                <div key={String(label)} className="flex items-center justify-between">
                  <span className="text-muted">{label}</span>
                  <span className="font-mono text-text">{value ?? "n/a"}</span>
                </div>
              ))}
              {[
                ["Non-ASCII ratio", obfuscation.non_ascii_ratio],
                ["Short-name ratio", obfuscation.short_ratio],
              ].map(([label, ratio]) => (
                <div key={String(label)} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-muted">{label}</span>
                    <span className="font-mono text-text">{((Number(ratio) || 0) * 100).toFixed(1)}%</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-panel-2 overflow-hidden">
                    <div
                      className="h-full bg-high"
                      style={{ width: `${Math.min(100, (Number(ratio) || 0) * 100)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
          <div className="pt-2 border-t border-border flex items-start space-x-1.5 text-[11px] text-muted">
            <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <span>Heuristics are advisory; verify with ILSpyCmd output before concluding obfuscation.</span>
          </div>
        </div>
      </div>
    </div>
  );
}
