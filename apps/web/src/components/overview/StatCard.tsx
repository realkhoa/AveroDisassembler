import React, { type ReactNode } from "react";
import Link from "next/link";

/**
 * @file StatCard.tsx
 * @brief Reusable summary metric card for overview triage dashboard.
 */

interface StatCardProps {
  label: string;
  value: string | number;
  subValue?: string;
  icon?: ReactNode;
  href?: string;
}

/**
 * @brief Summary statistic card component.
 */
export function StatCard({ label, value, subValue, icon, href }: StatCardProps) {
  const content = (
    <div className="p-4 rounded-card bg-panel border border-border hover:border-muted/50 transition-all flex flex-col justify-between">
      <div className="flex items-center justify-between text-muted text-xs mb-2">
        <span>{label}</span>
        {icon && <div className="text-muted">{icon}</div>}
      </div>
      <div>
        <div className="text-xl font-bold text-text font-mono">{value}</div>
        {subValue && <div className="text-[11px] text-muted mt-0.5">{subValue}</div>}
      </div>
    </div>
  );

  if (href) {
    return <Link href={href} className="block transition-transform hover:-translate-y-0.5">{content}</Link>;
  }

  return content;
}
