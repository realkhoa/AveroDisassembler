"use client";

/**
 * @file page.tsx
 * @brief AndroidManifest & APK structure audit route (/report/[reportId]/manifest).
 */

import React, { useEffect, useState, use } from "react";
import { ShieldAlert, AlertTriangle, CheckCircle2, ShieldCheck, Lock, Unlock } from "lucide-react";
import { useReport } from "@/lib/report-context";
import type { AveroReport } from "@/types/report";

interface ManifestPageProps {
  params: Promise<{ reportId: string }>;
}

interface ComponentEntry {
  kind: string;
  name: string;
  exported: boolean;
  permission: string | null;
}

/**
 * @brief AndroidManifest audit page component.
 * @param props Route props containing unresolved dynamic params.
 * @return React element representing the APK manifest page.
 */
export default function ManifestPage({ params }: ManifestPageProps) {
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
        <div className="text-xs text-muted">Loading APK manifest facts...</div>
      </div>
    );
  }

  const apk = (report.facts?.["apk.structure"] as Record<string, unknown>) || {};
  const components = (apk.apk_components as ComponentEntry[]) || [];
  const dangerousPermissions = (apk.apk_dangerous_permissions as string[]) || [];
  const allPermissions = (apk.apk_permissions as string[]) || [];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text">APK AndroidManifest Audit</h1>
        <p className="text-xs text-muted">
          Review package identity, SDK level boundaries, exported components, and declared permission risks.
        </p>
      </div>

      {/* High-Risk Banners */}
      {apk.apk_debuggable === true && (
        <div className="p-4 rounded-card bg-critical/10 border border-critical/40 flex items-start space-x-3 text-critical text-xs">
          <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-bold text-sm">Critical Risk: android:debuggable=&quot;true&quot;</div>
            <p className="text-text/90">
              Debuggable builds allow arbitrary Java debugger (JDWP) attachment, memory inspection, and runtime manipulation on non-rooted devices.
            </p>
          </div>
        </div>
      )}

      {/* Package Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3.5 rounded-card bg-panel border border-border">
          <span className="text-[11px] text-muted block">Package Name</span>
          <span className="font-mono text-xs font-bold text-text break-all">
            {String(apk.apk_package || "N/A")}
          </span>
        </div>
        <div className="p-3.5 rounded-card bg-panel border border-border">
          <span className="text-[11px] text-muted block">Version</span>
          <span className="font-mono text-xs font-bold text-text">
            {String(apk.apk_version_name || "N/A")} (code {String(apk.apk_version_code || "")})
          </span>
        </div>
        <div className="p-3.5 rounded-card bg-panel border border-border">
          <span className="text-[11px] text-muted block">SDK Targets</span>
          <span className="font-mono text-xs font-bold text-text">
            Min {String(apk.apk_min_sdk || "N/A")} · Target {String(apk.apk_target_sdk || "N/A")}
          </span>
        </div>
        <div className="p-3.5 rounded-card bg-panel border border-border">
          <span className="text-[11px] text-muted block">Backup Allowed</span>
          <span className="font-mono text-xs font-bold text-text">
            {apk.apk_allow_backup ? "true (allowBackup enabled)" : "false"}
          </span>
        </div>
      </div>

      {/* Permissions Breakdown */}
      <div className="rounded-card bg-panel border border-border overflow-hidden">
        <div className="p-3.5 border-b border-border bg-panel-2/60 flex items-center justify-between text-xs font-semibold text-text">
          <div className="flex items-center space-x-2">
            <Lock className="w-4 h-4 text-accent" />
            <span>Declared Permissions</span>
          </div>
          <span className="text-[11px] font-mono text-muted">
            {allPermissions.length} total ({dangerousPermissions.length} dangerous)
          </span>
        </div>

        <div className="divide-y divide-border/50 max-h-64 overflow-y-auto p-2">
          {allPermissions.length === 0 ? (
            <div className="p-6 text-center text-xs text-muted">No permissions requested.</div>
          ) : (
            allPermissions.map((perm) => {
              const isDangerous = dangerousPermissions.includes(perm);
              return (
                <div key={perm} className="py-2 px-3 flex items-center justify-between text-xs">
                  <span className="font-mono text-text">{perm}</span>
                  {isDangerous ? (
                    <span className="px-2 py-0.5 rounded-chip bg-high/20 text-high text-[10px] font-bold border border-high/40 uppercase">
                      Dangerous
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded-chip bg-panel-2 text-muted text-[10px] border border-border">
                      Normal
                    </span>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Android Components Table */}
      <div className="rounded-card bg-panel border border-border overflow-hidden">
        <div className="p-3.5 border-b border-border bg-panel-2/60 flex items-center justify-between text-xs font-semibold text-text">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-accent" />
            <span>Declared Android Components</span>
          </div>
          <span className="text-[11px] font-mono text-muted">{components.length} components</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-border bg-panel-2/40 text-muted uppercase tracking-wider text-[11px]">
                <th className="py-2.5 px-4 font-semibold w-28">Type</th>
                <th className="py-2.5 px-4 font-semibold">Component Class</th>
                <th className="py-2.5 px-4 font-semibold w-28">Exported</th>
                <th className="py-2.5 px-4 font-semibold">Permission Guard</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {components.map((comp, idx) => {
                const isRisky = comp.exported && !comp.permission;
                return (
                  <tr
                    key={`${comp.name}-${idx}`}
                    className={`hover:bg-panel-2/50 transition-colors ${
                      isRisky ? "bg-medium/5" : ""
                    }`}
                  >
                    <td className="py-2.5 px-4 font-mono uppercase text-muted text-[11px]">
                      {comp.kind}
                    </td>
                    <td className="py-2.5 px-4 font-mono font-medium text-text">
                      <div className="flex items-center space-x-2">
                        <span>{comp.name}</span>
                        {isRisky && (
                          <span
                            title="Exported without permission guard"
                            className="inline-flex items-center text-medium"
                          >
                            <AlertTriangle className="w-3.5 h-3.5" />
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2.5 px-4">
                      {comp.exported ? (
                        <span className="inline-flex items-center space-x-1 text-medium text-[11px] font-bold">
                          <Unlock className="w-3 h-3" />
                          <span>true</span>
                        </span>
                      ) : (
                        <span className="text-muted text-[11px]">false</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[11px]">
                      {comp.permission ? (
                        <span className="text-low font-semibold">{comp.permission}</span>
                      ) : comp.exported ? (
                        <span className="text-medium font-semibold">None (Accessible to all apps)</span>
                      ) : (
                        <span className="text-muted">Private</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
