import React from "react";
import type { Severity } from "@/types/report";

/**
 * @file SeverityBadge.tsx
 * @brief Accessible badge pairing severity color with text label and icon.
 */

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

/**
 * @brief Renders a severity badge conforming to WCAG AA color and text guidelines.
 */
export function SeverityBadge({ severity, className = "" }: SeverityBadgeProps) {
  const styles: Record<Severity, { bg: string; text: string; border: string }> = {
    critical: { bg: "bg-critical/20", text: "text-critical", border: "border-critical/40" },
    high: { bg: "bg-high/20", text: "text-high", border: "border-high/40" },
    medium: { bg: "bg-medium/20", text: "text-medium", border: "border-medium/40" },
    low: { bg: "bg-low/20", text: "text-low", border: "border-low/40" },
    info: { bg: "bg-info/20", text: "text-info", border: "border-info/40" },
  };

  const current = styles[severity] || styles.info;

  return (
    <span
      className={`inline-flex items-center space-x-1.5 px-2 py-0.5 rounded-chip text-[11px] font-bold uppercase tracking-wider border ${current.bg} ${current.text} ${current.border} ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      <span>{severity}</span>
    </span>
  );
}
