"use client";

/**
 * @file EvidenceInspector.tsx
 * @brief Master-detail inspector for browsing and verifying evidence items.
 */

import React, { useState, useMemo, useEffect } from "react";
import Link from "next/link";
import { Search, FileSearch, Binary, Copy, Check, ShieldAlert, Cpu } from "lucide-react";
import type { Evidence, Finding } from "@/types/report";
import { LocatorTable } from "./LocatorTable";
import { SeverityBadge } from "@/components/findings/SeverityBadge";

interface EvidenceInspectorProps {
  reportId: string;
  evidenceList: Evidence[];
  findings: Finding[];
  initialEvidenceId?: string | null;
}

/**
 * @brief Interactive evidence inspector component.
 */
export function EvidenceInspector({
  reportId,
  evidenceList,
  findings,
  initialEvidenceId,
}: EvidenceInspectorProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string>(
    initialEvidenceId || (evidenceList[0]?.id ?? "")
  );
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    if (initialEvidenceId) {
      setSelectedId(initialEvidenceId);
    }
  }, [initialEvidenceId]);

  // Build backlinks mapping: evidenceId -> Finding[]
  const backlinksMap = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of findings) {
      for (const evId of f.evidence_ids) {
        const list = map.get(evId) || [];
        list.push(f);
        map.set(evId, list);
      }
    }
    return map;
  }, [findings]);

  // Filter evidence list
  const filteredEvidence = useMemo(() => {
    if (!searchQuery.trim()) return evidenceList;
    const q = searchQuery.toLowerCase();
    return evidenceList.filter(
      (e) =>
        e.id.toLowerCase().includes(q) ||
        e.producer.engine.toLowerCase().includes(q) ||
        e.kind.toLowerCase().includes(q) ||
        e.excerpt.toLowerCase().includes(q)
    );
  }, [evidenceList, searchQuery]);

  const activeEvidence = useMemo(() => {
    return evidenceList.find((e) => e.id === selectedId) || evidenceList[0] || null;
  }, [evidenceList, selectedId]);

  const handleCopy = async (text: string, type: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(type);
    setTimeout(() => setCopied(null), 2000);
  };

  // Check if offset exists in locator for Hex jump
  const hexOffset = useMemo(() => {
    if (!activeEvidence?.locator) return null;
    const loc = activeEvidence.locator;
    if (typeof loc.file_offset === "number") return loc.file_offset;
    if (typeof loc.offset === "number") return loc.offset;
    if (typeof loc.rva === "number") return loc.rva;
    return null;
  }, [activeEvidence]);

  const referencingFindings = activeEvidence
    ? backlinksMap.get(activeEvidence.id) || []
    : [];

  return (
    <div className="grid grid-cols-1 md:grid-cols-12 gap-4 h-[calc(100vh-180px)] min-h-[500px]">
      {/* Left Column: Searchable List */}
      <div className="md:col-span-4 rounded-card bg-panel border border-border flex flex-col overflow-hidden">
        {/* Search bar */}
        <div className="p-3 border-b border-border">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-muted pointer-events-none" />
            <input
              type="text"
              placeholder="Search evidence ID or engine..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-bg border border-border text-xs rounded-input pl-8 pr-3 py-1.5 w-full text-text focus:border-accent focus:outline-none"
            />
          </div>
        </div>

        {/* List items */}
        <div className="flex-1 overflow-y-auto divide-y divide-border/50">
          {filteredEvidence.length === 0 ? (
            <div className="p-6 text-center text-xs text-muted">
              No matching evidence found.
            </div>
          ) : (
            filteredEvidence.map((ev) => {
              const isSelected = ev.id === activeEvidence?.id;
              const refCount = backlinksMap.get(ev.id)?.length || 0;

              return (
                <button
                  key={ev.id}
                  onClick={() => setSelectedId(ev.id)}
                  className={`w-full text-left p-3 text-xs transition-colors block ${
                    isSelected
                      ? "bg-accent/10 border-l-2 border-accent"
                      : "hover:bg-panel-2/60"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono font-semibold text-text">{ev.id}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded-chip bg-panel-2 text-muted border border-border">
                      {ev.kind}
                    </span>
                  </div>

                  <div className="text-[11px] text-muted flex items-center justify-between">
                    <span className="font-mono">{ev.producer.engine}</span>
                    {refCount > 0 && (
                      <span className="text-accent font-semibold">
                        {refCount} finding{refCount > 1 ? "s" : ""}
                      </span>
                    )}
                  </div>

                  <div className="text-[11px] text-muted/80 line-clamp-1 mt-1 font-mono">
                    {ev.excerpt}
                  </div>
                </button>
              );
            })
          )}
        </div>

        <div className="p-2.5 border-t border-border bg-panel-2/50 text-[11px] text-muted text-center">
          {evidenceList.length} evidence items recorded
        </div>
      </div>

      {/* Right Column: Active Evidence Inspector */}
      <div className="md:col-span-8 rounded-card bg-panel border border-border flex flex-col overflow-hidden">
        {!activeEvidence ? (
          <div className="flex-1 flex items-center justify-center text-xs text-muted">
            Select an evidence item to inspect its details and locator.
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto p-5 space-y-6">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-border">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <FileSearch className="w-5 h-5 text-accent" />
                  <h2 className="text-base font-bold text-text font-mono">
                    {activeEvidence.id}
                  </h2>
                </div>
                <div className="text-xs text-muted flex items-center space-x-2">
                  <span>Engine: <strong className="text-text font-mono">{activeEvidence.producer.engine}</strong> (v{activeEvidence.producer.version})</span>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleCopy(activeEvidence.id, "id")}
                  className="px-2.5 py-1.5 rounded-input bg-panel-2 hover:bg-border text-xs text-muted hover:text-text border border-border flex items-center space-x-1.5 transition-colors"
                >
                  {copied === "id" ? <Check className="w-3.5 h-3.5 text-low" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy ID</span>
                </button>

                {hexOffset !== null && (
                  <Link
                    href={`/report/${reportId}/hex?offset=${hexOffset}`}
                    className="px-3 py-1.5 rounded-input bg-accent/10 hover:bg-accent/20 text-accent text-xs font-semibold border border-accent/30 flex items-center space-x-1.5 transition-colors"
                  >
                    <Binary className="w-3.5 h-3.5" />
                    <span>View in Hex (0x{hexOffset.toString(16).toUpperCase()})</span>
                  </Link>
                )}
              </div>
            </div>

            {/* Locator Coordinates */}
            <div className="space-y-2">
              <span className="text-[11px] font-semibold text-muted uppercase tracking-wider block">
                Locator Coordinates
              </span>
              <LocatorTable locator={activeEvidence.locator} />
            </div>

            {/* Verifiable Excerpt */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-muted uppercase tracking-wider">
                  Verifiable Excerpt
                </span>
                <button
                  onClick={() => handleCopy(activeEvidence.excerpt, "excerpt")}
                  className="text-[11px] text-accent hover:underline flex items-center space-x-1"
                >
                  {copied === "excerpt" ? <Check className="w-3 h-3 text-low" /> : <Copy className="w-3 h-3" />}
                  <span>Copy Excerpt</span>
                </button>
              </div>

              <div className="p-3.5 rounded-card bg-bg border border-border font-mono text-xs text-text leading-relaxed whitespace-pre-wrap select-text">
                {activeEvidence.excerpt}
              </div>
            </div>

            {/* Referencing Findings (Backlinks) */}
            <div className="space-y-2">
              <span className="text-[11px] font-semibold text-muted uppercase tracking-wider block">
                Referenced By Findings ({referencingFindings.length})
              </span>

              {referencingFindings.length === 0 ? (
                <div className="text-xs text-muted p-3 rounded-input bg-bg border border-border">
                  This evidence item is not directly referenced by any finding.
                </div>
              ) : (
                <div className="space-y-2">
                  {referencingFindings.map((f) => (
                    <Link
                      key={f.id}
                      href={`/report/${reportId}/findings?finding=${f.id}`}
                      className="p-3 rounded-card bg-bg border border-border hover:border-accent/40 flex items-center justify-between transition-colors group block"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <SeverityBadge severity={f.severity} />
                          <span className="text-xs font-semibold text-text group-hover:text-accent transition-colors">
                            {f.title}
                          </span>
                        </div>
                        <div className="text-[11px] text-muted line-clamp-1">
                          {f.detail}
                        </div>
                      </div>
                      <ShieldAlert className="w-4 h-4 text-muted group-hover:text-accent shrink-0 ml-3" />
                    </Link>
                  ))}
                </div>
              )}
            </div>

            {/* Limitations if present */}
            {activeEvidence.limitations && activeEvidence.limitations.length > 0 && (
              <div className="space-y-1.5 p-3 rounded-card bg-medium/10 border border-medium/30 text-xs text-medium">
                <div className="font-semibold">Analyzer Limitations:</div>
                <ul className="list-disc list-inside space-y-0.5">
                  {activeEvidence.limitations.map((lim, idx) => (
                    <li key={idx}>{lim}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
