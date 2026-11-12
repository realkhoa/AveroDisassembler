"use client";

/**
 * @file HexViewer.tsx
 * @brief Virtualized, paged hex viewer with address gutter, byte grid, and ASCII preview.
 */

import React, { useState, useEffect, useRef } from "react";
import { Binary, ChevronLeft, ChevronRight, Upload, Search } from "lucide-react";
import { getDataSource } from "@/lib/data-source";
import type { HexSlice } from "@/lib/data-source/types";

interface HexViewerProps {
  reportId: string;
  initialOffset?: number;
}

const PAGE_SIZE = 512; // 32 rows of 16 bytes

/**
 * @brief Hex editor and viewer component.
 */
export function HexViewer({ reportId, initialOffset = 0 }: HexViewerProps) {
  const [currentOffset, setCurrentOffset] = useState<number>(initialOffset);
  const [hexSlice, setHexSlice] = useState<HexSlice | null>(null);
  const [selectedByteOffset, setSelectedByteOffset] = useState<number | null>(null);
  const [targetOffsetInput, setTargetOffsetInput] = useState<string>(
    `0x${initialOffset.toString(16).toUpperCase()}`
  );
  const [isLoading, setIsLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchHex = async (offset: number) => {
    setIsLoading(true);
    try {
      const dataSource = getDataSource();
      const slice = await dataSource.getHex(reportId, offset, PAGE_SIZE);
      setHexSlice(slice);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHex(currentOffset);
  }, [reportId, currentOffset]);

  const handleUploadBinary = async (file: File) => {
    const arrayBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);
    const dataSource = getDataSource();
    if ("setArtifactBytes" in dataSource && typeof dataSource.setArtifactBytes === "function") {
      dataSource.setArtifactBytes(reportId, bytes);
      fetchHex(currentOffset);
    }
  };

  const handleJump = (e: React.FormEvent) => {
    e.preventDefault();
    let parsed = 0;
    const clean = targetOffsetInput.trim().toLowerCase();
    if (clean.startsWith("0x")) {
      parsed = parseInt(clean.slice(2), 16);
    } else {
      parsed = parseInt(clean, 10);
    }

    if (!isNaN(parsed) && parsed >= 0) {
      setCurrentOffset(parsed);
    }
  };

  const handlePrevPage = () => {
    setCurrentOffset((prev) => Math.max(0, prev - PAGE_SIZE));
  };

  const handleNextPage = () => {
    if (hexSlice && currentOffset + PAGE_SIZE < hexSlice.totalSize) {
      setCurrentOffset((prev) => prev + PAGE_SIZE);
    }
  };

  if (!hexSlice) {
    return (
      <div className="p-12 rounded-card bg-panel border border-border text-center space-y-4">
        <div className="w-12 h-12 rounded-full bg-panel-2 border border-border flex items-center justify-center text-accent mx-auto">
          <Binary className="w-6 h-6" />
        </div>
        <div className="space-y-1">
          <h3 className="text-base font-bold text-text">Artifact Bytes Required</h3>
          <p className="text-xs text-muted max-w-md mx-auto">
            The report JSON stores triage metadata. To inspect raw binary hex instructions and byte slices, please select the original artifact binary file.
          </p>
        </div>

        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleUploadBinary(e.target.files[0]);
            }
          }}
        />

        <button
          onClick={() => fileInputRef.current?.click()}
          className="px-4 py-2 rounded-input bg-accent hover:bg-accent/90 text-bg text-xs font-semibold inline-flex items-center space-x-2 transition-colors"
        >
          <Upload className="w-4 h-4" />
          <span>Provide Original Artifact File</span>
        </button>
      </div>
    );
  }

  // Generate 16-byte rows
  const rows: Array<{ address: number; bytes: number[] }> = [];
  for (let i = 0; i < hexSlice.bytes.length; i += 16) {
    const chunk: number[] = [];
    for (let j = 0; j < 16; j++) {
      if (i + j < hexSlice.bytes.length) {
        chunk.push(hexSlice.bytes[i + j]);
      }
    }
    rows.push({
      address: hexSlice.offset + i,
      bytes: chunk,
    });
  }

  const selectedByteVal =
    selectedByteOffset !== null &&
    selectedByteOffset >= hexSlice.offset &&
    selectedByteOffset < hexSlice.offset + hexSlice.bytes.length
      ? hexSlice.bytes[selectedByteOffset - hexSlice.offset]
      : null;

  return (
    <div className="space-y-3 font-mono">
      {/* Navigation Toolbar */}
      <div className="p-3 rounded-card bg-panel border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <form onSubmit={handleJump} className="flex items-center space-x-2">
          <span className="text-muted text-[11px] font-sans">Jump to Offset:</span>
          <input
            type="text"
            value={targetOffsetInput}
            onChange={(e) => setTargetOffsetInput(e.target.value)}
            className="bg-bg border border-border rounded-input px-2.5 py-1 text-xs text-text w-32 focus:border-accent focus:outline-none"
          />
          <button
            type="submit"
            className="px-3 py-1 rounded-input bg-panel-2 hover:bg-border text-xs text-text border border-border"
          >
            Go
          </button>
        </form>

        <div className="flex items-center space-x-3">
          <span className="text-muted text-[11px] font-sans">
            Offset: <strong className="text-text font-mono">0x{currentOffset.toString(16).toUpperCase()}</strong> /{" "}
            {(hexSlice.totalSize / 1024).toFixed(1)} KB
          </span>

          <div className="flex items-center space-x-1">
            <button
              onClick={handlePrevPage}
              disabled={currentOffset === 0 || isLoading}
              className="p-1 rounded bg-panel-2 hover:bg-border disabled:opacity-40 text-text border border-border"
              title="Previous Page (512 bytes)"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={handleNextPage}
              disabled={currentOffset + PAGE_SIZE >= hexSlice.totalSize || isLoading}
              className="p-1 rounded bg-panel-2 hover:bg-border disabled:opacity-40 text-text border border-border"
              title="Next Page (512 bytes)"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Hex Grid Viewport */}
      <div className="p-4 rounded-card bg-panel border border-border overflow-x-auto select-text text-xs leading-relaxed">
        {/* Header row: Offset indicators 00 01 02 ... 0F */}
        <div className="flex items-center pb-2 mb-2 border-b border-border/60 text-muted font-bold text-[11px]">
          <div className="w-24 select-none">Offset</div>
          <div className="flex-1 grid grid-cols-16 gap-x-2 text-center max-w-[420px]">
            {Array.from({ length: 16 }).map((_, i) => (
              <span key={i}>{i.toString(16).toUpperCase().padStart(2, "0")}</span>
            ))}
          </div>
          <div className="w-40 pl-4 select-none">ASCII Preview</div>
        </div>

        {/* Data rows */}
        <div className="space-y-1">
          {rows.map((row) => (
            <div key={row.address} className="flex items-center hover:bg-panel-2/50 py-0.5 rounded">
              {/* Address Gutter */}
              <div className="w-24 text-muted text-[11px] select-none">
                0x{row.address.toString(16).toUpperCase().padStart(8, "0")}
              </div>

              {/* 16 Hex Bytes */}
              <div className="flex-1 grid grid-cols-16 gap-x-2 text-center max-w-[420px]">
                {Array.from({ length: 16 }).map((_, i) => {
                  const b = row.bytes[i];
                  const absOffset = row.address + i;
                  const isSelected = selectedByteOffset === absOffset;

                  if (b === undefined) {
                    return <span key={i} className="text-muted/20 select-none">··</span>;
                  }

                  return (
                    <button
                      key={i}
                      type="button"
                      onClick={() => setSelectedByteOffset(absOffset)}
                      className={`text-center rounded px-0.5 transition-colors ${
                        isSelected
                          ? "bg-accent text-bg font-bold"
                          : b === 0
                          ? "text-muted/40 hover:text-muted"
                          : "text-text hover:bg-accent/20"
                      }`}
                    >
                      {b.toString(16).toUpperCase().padStart(2, "0")}
                    </button>
                  );
                })}
              </div>

              {/* ASCII representation */}
              <div className="w-40 pl-4 text-text/80 tracking-widest text-[11px] whitespace-pre truncate">
                {row.bytes.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("")}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Selected byte inspector */}
      {selectedByteOffset !== null && selectedByteVal !== null && (
        <div className="p-3 rounded-card bg-panel border border-border text-xs flex items-center justify-between text-muted">
          <div>
            Offset: <span className="text-text font-bold">0x{selectedByteOffset.toString(16).toUpperCase()}</span> ({selectedByteOffset})
          </div>
          <div className="flex items-center space-x-4">
            <span>Hex: <strong className="text-accent font-bold">0x{selectedByteVal.toString(16).toUpperCase().padStart(2, "0")}</strong></span>
            <span>Dec: <strong className="text-text font-bold">{selectedByteVal}</strong></span>
            <span>Char: <strong className="text-text font-bold">{selectedByteVal >= 32 && selectedByteVal <= 126 ? `'${String.fromCharCode(selectedByteVal)}'` : "non-printable"}</strong></span>
          </div>
        </div>
      )}
    </div>
  );
}
