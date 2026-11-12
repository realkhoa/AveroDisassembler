"use client";

/**
 * @file FindingsTable.tsx
 * @brief Filterable, accessible findings table with keyboard navigation and detail inspection.
 */

import React, { useState, useMemo, useEffect, useCallback } from "react";
import { Search, Filter, ShieldAlert, ArrowUpDown, X } from "lucide-react";
import type { Finding, Severity } from "@/types/report";
import { SeverityBadge } from "./SeverityBadge";
import { FindingDrawer } from "./FindingDrawer";

interface FindingsTableProps {
  reportId: string;
  findings: Finding[];
  initialSeverity?: Severity | null;
  initialFindingId?: string | null;
}

/**
 * @brief Findings table component with multi-factor filtering.
 */
export function FindingsTable({
  reportId,
  findings,
  initialSeverity,
  initialFindingId,
}: FindingsTableProps) {
  const [selectedSeverities, setSelectedSeverities] = useState<Severity[]>(
    initialSeverity ? [initialSeverity] : []
  );
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [focusedIndex, setFocusedIndex] = useState<number>(-1);

  // Set initial finding from deep link if present
  useEffect(() => {
    if (initialFindingId) {
      const match = findings.find((f) => f.id === initialFindingId);
      if (match) {
        setSelectedFinding(match);
      }
    }
  }, [initialFindingId, findings]);

  // Extract unique categories
  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const f of findings) {
      if (f.category) set.add(f.category);
    }
    return Array.from(set).sort();
  }, [findings]);

  // Filtered findings
  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (selectedSeverities.length > 0 && !selectedSeverities.includes(f.severity)) {
        return false;
      }
      if (categoryFilter !== "all" && f.category !== categoryFilter) {
        return false;
      }
      if (searchQuery.trim().length > 0) {
        const q = searchQuery.toLowerCase();
        const matchesTitle = f.title.toLowerCase().includes(q);
        const matchesDetail = f.detail.toLowerCase().includes(q);
        const matchesCat = f.category.toLowerCase().includes(q);
        if (!matchesTitle && !matchesDetail && !matchesCat) {
          return false;
        }
      }
      return true;
    });
  }, [findings, selectedSeverities, categoryFilter, searchQuery]);

  // Keyboard navigation (j/k)
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }

      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setFocusedIndex((prev) => {
          const next = Math.min(prev + 1, filtered.length - 1);
          if (filtered[next]) setSelectedFinding(filtered[next]);
          return next;
        });
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setFocusedIndex((prev) => {
          const next = Math.max(prev - 1, 0);
          if (filtered[next]) setSelectedFinding(filtered[next]);
          return next;
        });
      }
    },
    [filtered]
  );

  useEffect(() => {
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);

  const toggleSeverity = (sev: Severity) => {
    setSelectedSeverities((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
    );
  };

  const clearAllFilters = () => {
    setSelectedSeverities([]);
    setCategoryFilter("all");
    setSearchQuery("");
  };

  const allSeverities: Severity[] = ["critical", "high", "medium", "low", "info"];

  return (
    <div className="space-y-4">
      {/* Filters Toolbar */}
      <div className="p-3.5 rounded-card bg-panel border border-border flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Left: Text Search & Category Dropdown */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-muted pointer-events-none" />
            <input
              type="text"
              placeholder="Filter findings by text..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-bg border border-border text-xs rounded-input pl-8 pr-3 py-1.5 w-60 text-text focus:border-accent focus:outline-none"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-2 top-2 text-muted hover:text-text"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          <div className="flex items-center space-x-1.5 text-xs text-muted">
            <Filter className="w-3.5 h-3.5" />
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="bg-bg border border-border rounded-input px-2.5 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
            >
              <option value="all">All Categories ({categories.length})</option>
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Right: Severity Toggles */}
        <div className="flex flex-wrap items-center gap-1.5">
          {allSeverities.map((sev) => {
            const isSelected = selectedSeverities.includes(sev);
            return (
              <button
                key={sev}
                type="button"
                onClick={() => toggleSeverity(sev)}
                className={`text-[11px] font-bold uppercase tracking-wider px-2 py-1 rounded-chip border transition-all ${
                  isSelected
                    ? "bg-accent/20 border-accent text-accent"
                    : "bg-panel-2 border-border text-muted hover:text-text hover:border-muted"
                }`}
              >
                {sev}
              </button>
            );
          })}

          {(selectedSeverities.length > 0 || categoryFilter !== "all" || searchQuery) && (
            <button
              onClick={clearAllFilters}
              className="text-xs text-muted hover:text-text underline px-2 py-1"
            >
              Reset
            </button>
          )}
        </div>
      </div>

      {/* Findings Table */}
      <div className="rounded-card bg-panel border border-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-border bg-panel-2/80 text-muted uppercase tracking-wider text-[11px]">
                <th className="py-2.5 px-4 font-semibold w-28">Severity</th>
                <th className="py-2.5 px-4 font-semibold">Title & Observation</th>
                <th className="py-2.5 px-4 font-semibold w-32">Category</th>
                <th className="py-2.5 px-4 font-semibold w-28">Confidence</th>
                <th className="py-2.5 px-4 font-semibold w-24 text-right">Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-muted">
                    <ShieldAlert className="w-8 h-8 text-muted/50 mx-auto mb-2" />
                    <div>No findings matched the selected criteria.</div>
                    <button
                      onClick={clearAllFilters}
                      className="mt-2 text-xs text-accent hover:underline"
                    >
                      Clear all active filters
                    </button>
                  </td>
                </tr>
              ) : (
                filtered.map((f, idx) => {
                  const isSelected = selectedFinding?.id === f.id;
                  return (
                    <tr
                      key={f.id}
                      onClick={() => {
                        setSelectedFinding(f);
                        setFocusedIndex(idx);
                      }}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? "bg-accent/10 border-l-2 border-accent"
                          : "hover:bg-panel-2/70"
                      }`}
                    >
                      <td className="py-3 px-4 whitespace-nowrap">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-semibold text-text">{f.title}</div>
                        <div className="text-muted text-[11px] line-clamp-1 mt-0.5">
                          {f.detail}
                        </div>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="font-mono text-muted bg-bg px-2 py-0.5 rounded border border-border">
                          {f.category}
                        </span>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap font-mono text-muted">
                        {(f.confidence * 100).toFixed(0)}%
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-right font-mono font-bold text-accent">
                        {f.evidence_ids.length}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Footer info */}
        <div className="p-3 border-t border-border bg-panel-2/50 text-[11px] text-muted flex items-center justify-between">
          <span>
            Showing <strong className="text-text">{filtered.length}</strong> of{" "}
            <strong>{findings.length}</strong> findings
          </span>
          <span className="hidden sm:inline">Use <kbd className="bg-bg px-1.5 py-0.5 rounded border border-border">j</kbd> / <kbd className="bg-bg px-1.5 py-0.5 rounded border border-border">k</kbd> to navigate</span>
        </div>
      </div>

      {/* Slide-over Finding Drawer */}
      <FindingDrawer
        reportId={reportId}
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
