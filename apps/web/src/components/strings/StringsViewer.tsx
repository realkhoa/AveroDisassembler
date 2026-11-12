"use client";

/**
 * @file StringsViewer.tsx
 * @brief High-performance virtualized strings table supporting 100k+ entries.
 */

import React, { useState, useMemo, useRef } from "react";
import Link from "next/link";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Search, Copy, Check, Binary, Filter } from "lucide-react";
import type { StringEntry } from "@/types/report";

interface StringsViewerProps {
  reportId: string;
  strings: StringEntry[];
}

/**
 * @brief Virtualized strings list component.
 */
export function StringsViewer({ reportId, strings }: StringsViewerProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [encodingFilter, setEncodingFilter] = useState<string>("all");
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);

  const parentRef = useRef<HTMLDivElement>(null);

  // Filtered dataset
  const filtered = useMemo(() => {
    let result = strings;
    if (encodingFilter !== "all") {
      const enc = encodingFilter.toLowerCase();
      result = result.filter((s) => s.encoding.toLowerCase() === enc);
    }
    if (searchQuery.trim().length > 0) {
      const q = searchQuery.toLowerCase();
      result = result.filter((s) => s.value.toLowerCase().includes(q));
    }
    return result;
  }, [strings, encodingFilter, searchQuery]);

  // Virtualizer for smooth 60fps scrolling
  const rowVirtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 36,
    overscan: 10,
  });

  const handleCopyOne = async (val: string, idx: number) => {
    await navigator.clipboard.writeText(val);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 1500);
  };

  const handleCopyAll = async () => {
    const text = filtered.slice(0, 10000).map((s) => s.value).join("\n");
    await navigator.clipboard.writeText(text);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  };

  return (
    <div className="space-y-3">
      {/* Search and Filter Toolbar */}
      <div className="p-3.5 rounded-card bg-panel border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-muted pointer-events-none" />
            <input
              type="text"
              placeholder="Search extracted strings..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-bg border border-border text-xs rounded-input pl-8 pr-3 py-1.5 w-64 text-text focus:border-accent focus:outline-none"
            />
          </div>

          <div className="flex items-center space-x-1 text-xs text-muted">
            <Filter className="w-3.5 h-3.5" />
            <select
              value={encodingFilter}
              onChange={(e) => setEncodingFilter(e.target.value)}
              className="bg-bg border border-border rounded-input px-2.5 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
            >
              <option value="all">All Encodings</option>
              <option value="ascii">ASCII</option>
              <option value="utf16le">UTF-16LE</option>
            </select>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs">
          <span className="text-muted font-mono text-[11px]">
            {filtered.length.toLocaleString()} of {strings.length.toLocaleString()} strings
          </span>
          <button
            onClick={handleCopyAll}
            disabled={filtered.length === 0}
            className="px-2.5 py-1.5 rounded-input bg-panel-2 hover:bg-border text-xs text-muted hover:text-text border border-border transition-colors flex items-center space-x-1"
          >
            {copiedAll ? <Check className="w-3.5 h-3.5 text-low" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy Filtered</span>
          </button>
        </div>
      </div>

      {/* Virtualized Table Container */}
      <div className="rounded-card bg-panel border border-border overflow-hidden">
        {/* Table Header */}
        <div className="grid grid-cols-12 px-4 py-2.5 border-b border-border bg-panel-2/80 text-[11px] font-semibold text-muted uppercase tracking-wider select-none">
          <div className="col-span-2 font-mono">Offset</div>
          <div className="col-span-2">Encoding</div>
          <div className="col-span-2">Section</div>
          <div className="col-span-5">Value</div>
          <div className="col-span-1 text-right">Action</div>
        </div>

        {/* Scrollable Virtual Viewport */}
        <div
          ref={parentRef}
          className="h-[550px] overflow-y-auto relative divide-y divide-border/30"
        >
          {filtered.length === 0 ? (
            <div className="p-12 text-center text-xs text-muted">
              No strings match the current search filter.
            </div>
          ) : (
            <div
              style={{
                height: `${rowVirtualizer.getTotalSize()}px`,
                width: "100%",
                position: "relative",
              }}
            >
              {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                const s = filtered[virtualRow.index];
                return (
                  <div
                    key={virtualRow.index}
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: "100%",
                      height: `${virtualRow.size}px`,
                      transform: `translateY(${virtualRow.start}px)`,
                    }}
                    className="grid grid-cols-12 items-center px-4 text-xs hover:bg-panel-2/50 transition-colors"
                  >
                    <div className="col-span-2 font-mono text-muted">
                      0x{s.offset.toString(16).toUpperCase()}
                    </div>
                    <div className="col-span-2">
                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-bg text-muted border border-border uppercase">
                        {s.encoding}
                      </span>
                    </div>
                    <div className="col-span-2 font-mono text-muted text-[11px]">
                      {s.section || "—"}
                    </div>
                    <div className="col-span-5 font-mono text-text truncate pr-2" title={s.value}>
                      {s.value}
                    </div>
                    <div className="col-span-1 flex items-center justify-end space-x-1.5">
                      <button
                        onClick={() => handleCopyOne(s.value, virtualRow.index)}
                        title="Copy string value"
                        className="p-1 rounded text-muted hover:text-text hover:bg-panel"
                      >
                        {copiedIdx === virtualRow.index ? (
                          <Check className="w-3.5 h-3.5 text-low" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                      <Link
                        href={`/report/${reportId}/hex?offset=${s.offset}`}
                        title="Jump to Hex"
                        className="p-1 rounded text-muted hover:text-accent hover:bg-panel"
                      >
                        <Binary className="w-3.5 h-3.5" />
                      </Link>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
