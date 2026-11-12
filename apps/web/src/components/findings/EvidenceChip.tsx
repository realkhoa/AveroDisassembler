import React from "react";
import Link from "next/link";
import { FileSearch } from "lucide-react";

/**
 * @file EvidenceChip.tsx
 * @brief Interactive chip linking a finding to its underlying evidence.
 */

interface EvidenceChipProps {
  reportId: string;
  evidenceId: string;
}

/**
 * @brief Clickable chip directing to the Evidence Inspector.
 */
export function EvidenceChip({ reportId, evidenceId }: EvidenceChipProps) {
  return (
    <Link
      href={`/report/${reportId}/evidence?id=${evidenceId}`}
      className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-chip bg-accent/10 hover:bg-accent/20 text-accent border border-accent/30 text-xs font-mono transition-colors"
      title={`Inspect evidence ${evidenceId}`}
    >
      <FileSearch className="w-3.5 h-3.5" />
      <span>evidence:{evidenceId.slice(0, 8)}</span>
    </Link>
  );
}
