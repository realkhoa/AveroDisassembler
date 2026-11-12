"use client";

/**
 * @file page.tsx
 * @brief Decompile route (/report/[reportId]/decompile) — API mode only (M3).
 */

import React, { useEffect, useRef, useState, use } from "react";
import { Code2, Play, Loader2, AlertCircle, Copy, Check, FileCode, Server } from "lucide-react";
import { useReport } from "@/lib/report-context";
import type { AveroReport } from "@/types/report";
import type { DecompileEngine, DecompileFile, DecompileResult } from "@/types/api";

interface DecompilePageProps {
  params: Promise<{ reportId: string }>;
}

/**
 * @brief Decompile screen: engine/type selection, SSE job progress and read-only code output.
 */
export default function DecompilePage({ params }: DecompilePageProps) {
  const resolvedParams = use(params);
  const { activeReport, loadReportById, mode, source } = useReport();
  const [report, setReport] = useState<AveroReport | null>(activeReport);
  const [engine, setEngine] = useState<DecompileEngine>("ilspycmd");
  const [typeName, setTypeName] = useState("");
  const [limit, setLimit] = useState(50);
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<string | null>(null);
  const [percent, setPercent] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DecompileResult | null>(null);
  const [activeFile, setActiveFile] = useState(0);
  const [copied, setCopied] = useState(false);
  const unsubscribeRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    if (!report || report.artifact.id !== resolvedParams.reportId) {
      loadReportById(resolvedParams.reportId).then((loaded) => {
        if (loaded) setReport(loaded);
      });
    }
  }, [resolvedParams.reportId, report, loadReportById]);

  useEffect(() => {
    if (report?.artifact.kinds.includes("dotnet")) {
      setEngine("ilspycmd");
    }
    return () => unsubscribeRef.current?.();
  }, [report]);

  if (mode !== "API") {
    return (
      <div className="p-4 rounded-card bg-panel border border-border space-y-2">
        <div className="flex items-center space-x-2 text-high text-sm font-semibold">
          <Server className="w-4 h-4" />
          <span>Decompilation requires API mode</span>
        </div>
        <p className="text-xs text-muted">
          Start <code className="text-accent">avero serve</code> and switch to API mode in Settings.
          Engines are installed with <code className="text-accent">avero engine install</code>.
        </p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-3">
        <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        <div className="text-xs text-muted">Loading report…</div>
      </div>
    );
  }

  const files: DecompileFile[] = result?.files || [];
  const selected = files[activeFile];

  const start = async () => {
    if (!source.decompile) return;
    setBusy(true);
    setError(null);
    setResult(null);
    setStage("queued");
    setPercent(0);
    setActiveFile(0);
    try {
      const job = await source.decompile(report.artifact.id, {
        engine,
        type: typeName.trim() || undefined,
        limit,
      });
      const handleEvent = (event: { type: string; stage?: string; percent?: number; error?: { message?: string }; result?: unknown }) => {
        if (event.type === "progress") {
          setStage(event.stage || "working");
          setPercent(event.percent || 0);
          return;
        }
        setBusy(false);
        setStage(null);
        if (event.type === "error") {
          setError(event.error?.message || "Decompilation failed");
          return;
        }
        const loadResult = async () => {
          try {
            const snapshot = await (source.getJob ? source.getJob(job.job_id) : Promise.resolve(null));
            const decompiled = (snapshot?.result || event.result) as DecompileResult | undefined;
            if (decompiled && Array.isArray(decompiled.files)) {
              setResult(decompiled);
            } else {
              setError("Decompile finished without result files");
            }
          } catch (loadError: unknown) {
            setError(loadError instanceof Error ? loadError.message : "Failed to load decompile result");
          }
        };
        void loadResult();
      };
      if (source.subscribeJob) {
        unsubscribeRef.current = source.subscribeJob(job.job_id, handleEvent);
      } else {
        setBusy(false);
        setStage(null);
        setError("SSE not supported by this data source");
      }
    } catch (decompileError: unknown) {
      setBusy(false);
      setStage(null);
      setError(decompileError instanceof Error ? decompileError.message : "Decompilation failed");
    }
  };

  const copyCode = async () => {
    if (!selected) return;
    await navigator.clipboard.writeText(selected.content);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text flex items-center space-x-2">
          <Code2 className="w-5 h-5 text-accent" />
          <span>Decompile</span>
        </h1>
        <p className="text-xs text-muted">
          Sidecar engines: ILSpyCmd for .NET, Ghidra headless for native (Ghidra requires JDK 25+).
        </p>
      </div>

      <form
        onSubmit={(event) => {
          event.preventDefault();
          void start();
        }}
        className="p-3 rounded-card bg-panel border border-border flex flex-wrap items-end gap-3"
      >
        <label className="space-y-1 text-xs">
          <span className="text-muted block">Engine</span>
          <select
            value={engine}
            onChange={(event) => setEngine(event.target.value as DecompileEngine)}
            className="bg-bg border border-border rounded-input px-2.5 py-1.5 text-text text-xs focus:border-accent focus:outline-none"
          >
            <option value="ilspycmd">ilspycmd (.NET)</option>
            <option value="ghidra">ghidra (native)</option>
          </select>
        </label>
        <label className="space-y-1 text-xs flex-1 min-w-[16rem]">
          <span className="text-muted block">
            {engine === "ilspycmd" ? "Type name (optional, all types if empty)" : "Function name/address (optional)"}
          </span>
          <input
            value={typeName}
            onChange={(event) => setTypeName(event.target.value)}
            placeholder={engine === "ilspycmd" ? "SampleLib.Class1" : "entry or 0x1400019c0"}
            className="w-full bg-bg border border-border rounded-input px-2.5 py-1.5 text-text font-mono focus:border-accent focus:outline-none"
          />
        </label>
        <label className="space-y-1 text-xs">
          <span className="text-muted block">Function limit</span>
          <input
            type="number"
            min={1}
            max={500}
            value={limit}
            onChange={(event) => setLimit(Number(event.target.value))}
            className="bg-bg border border-border rounded-input px-2.5 py-1.5 text-text font-mono w-24 focus:border-accent focus:outline-none"
          />
        </label>
        <button
          type="submit"
          disabled={busy}
          className="px-3 py-2 rounded-input bg-accent/10 hover:bg-accent/20 disabled:opacity-50 text-accent text-xs font-semibold border border-accent/30 flex items-center space-x-1.5"
        >
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
          <span>{busy ? "Decompiling…" : "Decompile"}</span>
        </button>
      </form>

      {busy && (
        <div className="space-y-1">
          <div className="flex items-center justify-between text-[11px] text-muted">
            <span className="font-mono">{stage || "queued"}</span>
            <span>{Math.round(percent)}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-panel-2 overflow-hidden">
            <div className="h-full bg-accent transition-all" style={{ width: `${Math.max(2, percent)}%` }} />
          </div>
        </div>
      )}

      {error && (
        <div className="flex items-start space-x-2 p-3 rounded-input bg-critical/10 border border-critical/30 text-critical text-xs">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <div>
            <div>{error}</div>
            {error.toLowerCase().includes("not installed") && (
              <div className="mt-1 text-muted">
                Install it in the Engines screen or run{" "}
                <code className="text-accent">
                  avero engine install {engine === "ghidra" ? "ghidra" : "ilspycmd"}
                </code>
                .
              </div>
            )}
          </div>
        </div>
      )}

      {files.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
          <div className="lg:col-span-1 rounded-card bg-panel border border-border overflow-hidden">
            <div className="px-3 py-2 border-b border-border text-[11px] text-muted uppercase tracking-wider">
              Files ({files.length})
            </div>
            <div className="max-h-[32rem] overflow-y-auto divide-y divide-border">
              {files.map((file, index) => (
                <button
                  key={`${file.name}-${index}`}
                  onClick={() => setActiveFile(index)}
                  className={`w-full text-left px-3 py-2 text-xs font-mono flex items-center space-x-2 ${
                    activeFile === index ? "bg-panel-2 text-accent" : "text-text hover:bg-panel-2/60"
                  }`}
                >
                  <FileCode className="w-3.5 h-3.5 shrink-0" />
                  <span className="truncate">{file.name || file.entry || `file-${index}`}</span>
                </button>
              ))}
            </div>
            {result?.program && (
              <div className="px-3 py-2 border-t border-border text-[10px] text-muted font-mono truncate">
                {result.program} · {result.language}
              </div>
            )}
          </div>

          <div className="lg:col-span-3 rounded-card bg-panel border border-border overflow-hidden">
            <div className="px-3 py-2 border-b border-border flex items-center justify-between">
              <span className="text-[11px] text-muted font-mono truncate">
                {selected?.name || selected?.entry || "output"}
              </span>
              <button
                onClick={() => void copyCode()}
                className="px-2 py-1 rounded-input bg-panel-2 hover:bg-border text-muted hover:text-text text-[11px] border border-border flex items-center space-x-1"
              >
                {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? "Copied" : "Copy"}</span>
              </button>
            </div>
            <pre className="p-3 text-[11px] leading-relaxed text-text font-mono overflow-auto max-h-[32rem] whitespace-pre">
              {selected?.content || ""}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
