"use client";

/**
 * @file Sidebar.tsx
 * @brief Navigation sidebar adapting to the active report kinds and adapter mode.
 */

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  AlertTriangle,
  FolderTree,
  FileSearch,
  Binary,
  Layers,
  FileCode,
  ShieldAlert,
  Database,
  Activity,
  Cpu,
  Code2,
  GitCompare,
  Package,
  FileSignature,
  TerminalSquare,
} from "lucide-react";
import { useReport } from "@/lib/report-context";

/** @brief Application sidebar component. */
export function Sidebar() {
  const pathname = usePathname();
  const { activeReport, mode } = useReport();
  const reportId = activeReport?.artifact?.id;
  const kinds = activeReport?.artifact?.kinds || [];
  const facts = activeReport?.facts || {};
  const findingsCount = activeReport?.findings?.length || 0;

  const basePath = reportId ? `/report/${reportId}` : "";
  const isApi = mode === "API";

  interface NavItem {
    label: string;
    href: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: number | string;
    show?: boolean;
    global?: boolean;
  }

  const hasDotnet = kinds.includes("dotnet") || Boolean(facts["dotnet.metadata"]);
  const hasSignatures = Boolean(facts["signatures.rules"]);

  const items: NavItem[] = [
    { label: "Overview", href: `${basePath}/overview`, icon: LayoutDashboard, show: true },
    {
      label: "Findings",
      href: `${basePath}/findings`,
      icon: AlertTriangle,
      badge: findingsCount > 0 ? findingsCount : undefined,
      show: true,
    },
    { label: "Evidence", href: `${basePath}/evidence`, icon: FileSearch, show: true },
    { label: "Sections", href: `${basePath}/sections`, icon: Layers, show: true },
    { label: "Imports & Exports", href: `${basePath}/imports`, icon: FolderTree, show: true },
    { label: "Strings", href: `${basePath}/strings`, icon: FileCode, show: true },
    { label: "Hex Viewer", href: `${basePath}/hex`, icon: Binary, show: true },
    { label: "APK Manifest", href: `${basePath}/manifest`, icon: ShieldAlert, show: kinds.includes("apk") },
    { label: ".NET Metadata", href: `${basePath}/dotnet`, icon: Cpu, show: hasDotnet },
    {
      label: "Signatures",
      href: `${basePath}/signatures`,
      icon: FileSignature,
      show: hasSignatures,
    },
    {
      label: "Disassembly",
      href: `${basePath}/disassembly`,
      icon: TerminalSquare,
      show: isApi,
    },
    { label: "Decompile", href: `${basePath}/decompile`, icon: Code2, show: isApi },
    { label: "Diff", href: `${basePath}/diff`, icon: GitCompare, show: isApi },
    { label: "Coverage & Unknowns", href: `${basePath}/coverage`, icon: Activity, show: true },
    { label: "Metadata", href: `${basePath}/metadata`, icon: Database, show: true },
    { label: "Engines", href: "/engines", icon: Package, show: true, global: true },
  ];

  return (
    <aside className="w-56 border-r border-border bg-panel flex flex-col justify-between select-none shrink-0 overflow-y-auto">
      <nav className="p-3 space-y-1">
        <div className="text-[11px] font-semibold tracking-wider text-muted px-2 py-1 uppercase">
          Navigation
        </div>

        {items
          .filter((item) => item.show)
          .map((item) => {
            const Icon = item.icon;
            const isClickable = item.global || Boolean(reportId);
            const isActive =
              isClickable && (item.global ? pathname === item.href : pathname.startsWith(item.href));

            if (!isClickable) {
              return (
                <div
                  key={item.label}
                  className="flex items-center justify-between px-2.5 py-2 rounded-input text-xs text-muted/50 cursor-not-allowed"
                >
                  <div className="flex items-center space-x-2.5">
                    <Icon className="w-4 h-4" />
                    <span>{item.label}</span>
                  </div>
                </div>
              );
            }

            return (
              <Link
                key={item.label}
                href={item.href}
                className={`flex items-center justify-between px-2.5 py-2 rounded-input text-xs font-medium transition-colors ${
                  isActive
                    ? "bg-panel-2 text-accent border border-accent/30 font-semibold"
                    : "text-text hover:bg-panel-2 hover:text-text border border-transparent"
                }`}
              >
                <div className="flex items-center space-x-2.5">
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span
                    className={`text-[11px] px-1.5 py-0.2 rounded-chip font-bold ${
                      typeof item.badge === "number" && item.badge > 0
                        ? "bg-high/20 text-high border border-high/40"
                        : "bg-panel-2 text-muted"
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </Link>
            );
          })}
      </nav>

      {activeReport && (
        <div className="p-3 border-t border-border text-[11px] text-muted space-y-1 bg-bg/50">
          <div>
            Format: <span className="text-text uppercase font-semibold">{kinds.join(", ") || "raw"}</span>
          </div>
          <div>
            Size: <span className="text-text font-mono">{(activeReport.artifact.size / 1024).toFixed(1)} KB</span>
          </div>
        </div>
      )}
    </aside>
  );
}
