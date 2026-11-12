"use client";

/**
 * @file FindingDrawer.tsx
 * @brief Slide-over inspector drawer displaying full details, remediation, and evidence.
 */

import React, { useEffect, useState } from "react";
import { X, Copy, Check, Wrench, ShieldAlert } from "lucide-react";
import type { Finding } from "@/types/report";
import { SeverityBadge } from "./SeverityBadge";
import { EvidenceChip } from "./EvidenceChip";

interface FindingDrawerProps {
  reportId: string;
  finding: Finding | null;
  onClose: () => void;
}

/**
 * @brief Detail drawer component for an inspected finding.
 */
export function FindingDrawer({ reportId, finding, onClose }: FindingDrawerProps) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  if (!finding) return null;

  const handleCopy = async () => {
    const text = `[${finding.severity.toUpperCase()}] ${finding.title}\nCategory: ${finding.category}\nConfidence: ${(finding.confidence * 100).toFixed(0)}%\n\n${finding.detail}${finding.remediation ? `\n\nRemediation:\n${finding.remediation}` : ""}`;
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-lg bg-panel border-l border-border shadow-2xl z-40 flex flex-col justify-between">
      {/* Header */}
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="w-5 h-5 text-accent" />
          <span className="font-semibold text-text text-sm">Finding Details</span>
          <span className="text-xs font-mono text-muted">({finding.id})</span>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleCopy}
            title="Copy finding details to clipboard"
            className="p-1.5 rounded hover:bg-panel-2 text-muted hover:text-text border border-transparent hover:border-border transition-colors text-xs flex items-center space-x-1"
          >
            {copied ? <Check className="w-4 h-4 text-low" /> : <Copy className="w-4 h-4" />}
          </button>
          <button
            onClick={onClose}
            title="Close drawer (Esc)"
            className="p-1.5 rounded hover:bg-panel-2 text-muted hover:text-text border border-transparent hover:border-border transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-6">
        {/* Severity, Category & Confidence */}
        <div className="space-y-2">
          <div className="flex items-center space-x-2">
            <SeverityBadge severity={finding.severity} />
            <span className="text-xs px-2 py-0.5 rounded-chip bg-panel-2 text-muted border border-border">
              {finding.category}
            </span>
            <span className="text-xs font-mono text-muted bg-bg px-2 py-0.5 rounded border border-border">
              {(finding.confidence * 100).toFixed(0)}% confidence
            </span>
          </div>

          <h2 className="text-base font-bold text-text leading-snug">
            {finding.title}
          </h2>
        </div>

        {/* Detailed description */}
        <div className="space-y-1.5">
          <span className="text-[11px] font-semibold text-muted uppercase tracking-wider block">
            Observation Details
          </span>
          <div className="p-3.5 rounded-card bg-bg border border-border text-xs text-text leading-relaxed whitespace-pre-wrap">
            {finding.detail}
          </div>
        </div>

        {/* Remediation guidance if present */}
        {finding.remediation && (
          <div className="space-y-1.5">
            <span className="text-[11px] font-semibold text-accent uppercase tracking-wider flex items-center space-x-1">
              <Wrench className="w-3.5 h-3.5" />
              <span>Recommended Remediation</span>
            </span>
            <div className="p-3.5 rounded-card bg-accent/5 border border-accent/20 text-xs text-text leading-relaxed">
              {finding.remediation}
            </div>
          </div>
        )}

        {/* Evidence linkage */}
        <div className="space-y-2">
          <span className="text-[11px] font-semibold text-muted uppercase tracking-wider block">
            Supporting Evidence ({finding.evidence_ids.length})
          </span>

          {finding.evidence_ids.length === 0 ? (
            <div className="text-xs text-muted">No evidence IDs linked to this finding.</div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {finding.evidence_ids.map((evId) => (
                <EvidenceChip key={evId} reportId={reportId} evidenceId={evId} />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Footer */}
      <div className="p-3 border-t border-border bg-bg/50 text-right">
        <button
          onClick={onClose}
          className="px-4 py-1.5 rounded-input bg-panel-2 hover:bg-border text-xs font-medium text-text border border-border transition-colors"
        >
          Close
        </button>
      </div>
    </div>
  );
}
