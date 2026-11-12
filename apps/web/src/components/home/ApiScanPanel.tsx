"use client";

/**
 * @file ApiScanPanel.tsx
 * @brief API-mode artifact upload with SSE scan progress (M2).
 */

import React, { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { UploadCloud, Server, AlertCircle, Loader2, Radio } from "lucide-react";
import { useReport } from "@/lib/report-context";
import type { JobEvent } from "@/types/api";

/**
 * @brief Uploads an artifact to `avero serve`, streams job progress over SSE and
 *        navigates to the report when the scan completes.
 */
export function ApiScanPanel() {
  const router = useRouter();
  const { source, apiHealth, apiError, refreshApiHealth } = useReport();
  const [file, setFile] = useState<File | null>(null);
  const [minStringLen, setMinStringLen] = useState(6);
  const [maxStrings, setMaxStrings] = useState(50000);
  const [only, setOnly] = useState("");
  const [skip, setSkip] = useState("");
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<string | null>(null);
  const [percent, setPercent] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const unsubscribeRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    return () => {
      unsubscribeRef.current?.();
    };
  }, []);

  const startScan = async () => {
    if (!file) {
      setError("Choose an artifact to scan first");
      return;
    }
    if (!source.scan) {
      setError("This data source does not support scanning");
      return;
    }
    setError(null);
    setBusy(true);
    setPercent(0);
    setStage("uploading");
    try {
      const scan = await source.scan(file, {
        min_string_len: minStringLen,
        max_strings: maxStrings,
        only: only.trim() || undefined,
        skip: skip.trim() || undefined,
      });
      setJobId(scan.job_id);

      const handleEvent = (event: JobEvent) => {
        if (event.type === "progress") {
          setStage(event.stage || "working");
          setPercent(event.percent || 0);
          return;
        }
        if (event.type === "error") {
          setStage(null);
          setBusy(false);
          setError(event.error?.message || "Scan failed");
          return;
        }
        const reportId =
          event.report_id ||
          (typeof event.result?.report_id === "string" ? event.result.report_id : undefined);
        if (reportId) {
          setPercent(100);
          setStage("done");
          router.push(`/report/${reportId}/overview`);
        } else {
          setBusy(false);
          setError("Scan finished without a report id");
        }
      };

      if (source.subscribeJob) {
        unsubscribeRef.current = source.subscribeJob(scan.job_id, handleEvent);
      } else {
        // Fallback: poll the job endpoint.
        const poll = async () => {
          if (!source.getJob) return;
          const job = await source.getJob(scan.job_id);
          if (job.status === "done") {
            const reportId =
              typeof job.result?.report_id === "string" ? job.result.report_id : undefined;
            if (reportId) router.push(`/report/${reportId}/overview`);
          } else if (job.status === "failed") {
            setBusy(false);
            setError(job.error?.message || "Scan failed");
          } else {
            setStage(job.stage || "working");
            setPercent(job.percent || 0);
            window.setTimeout(poll, 500);
          }
        };
        void poll();
      }
    } catch (scanError: unknown) {
      setBusy(false);
      setStage(null);
      setError(scanError instanceof Error ? scanError.message : "Scan request failed");
    }
  };

  if (!apiHealth) {
    return (
      <div className="w-full max-w-2xl mx-auto p-6 rounded-card bg-panel border border-border space-y-3">
        <div className="flex items-center space-x-2 text-high text-sm font-semibold">
          <Server className="w-4 h-4" />
          <span>API mode requires a running local daemon</span>
        </div>
        <p className="text-xs text-muted">
          Start it with <code className="text-accent">avero serve --port 8787</code> and retry.
          The daemon binds to loopback only; artifacts are processed locally.
        </p>
        {apiError && (
          <p className="text-xs text-critical font-mono break-all">{apiError}</p>
        )}
        <button
          onClick={() => void refreshApiHealth()}
          className="px-3 py-1.5 rounded-input bg-accent/10 hover:bg-accent/20 text-accent text-xs font-semibold border border-accent/30"
        >
          Retry connection
        </button>
      </div>
    );
  }

  return (
    <div className="w-full max-w-2xl mx-auto space-y-4">
      <div className="p-4 rounded-card bg-panel border border-border space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-text flex items-center space-x-2">
            <Radio className="w-4 h-4 text-accent" />
            <span>Scan artifact with avero serve</span>
          </h3>
          <span className="text-[11px] text-low font-mono">
            core {apiHealth.core_version}
          </span>
        </div>

        <label
          className={`flex flex-col items-center justify-center border-2 border-dashed rounded-input p-6 cursor-pointer transition-colors ${
            file ? "border-accent/50 bg-accent/5" : "border-border hover:border-muted"
          }`}
        >
          <input
            type="file"
            className="hidden"
            onChange={(event) => {
              const selected = event.target.files?.[0] || null;
              setFile(selected);
              setError(null);
            }}
          />
          <UploadCloud className="w-6 h-6 text-accent mb-2" />
          <span className="text-xs font-medium text-text">
            {file ? file.name : "Choose an artifact (PE, ELF, Mach-O, APK, metadata...)"}
          </span>
          <span className="text-[11px] text-muted mt-1">
            Uploaded to the loopback daemon and analyzed statically; never executed.
          </span>
        </label>

        <div className="grid grid-cols-2 gap-3 text-xs">
          <label className="space-y-1">
            <span className="text-muted block">Min string length</span>
            <input
              type="number"
              min={2}
              max={64}
              value={minStringLen}
              onChange={(event) => setMinStringLen(Number(event.target.value))}
              className="w-full bg-bg border border-border rounded-input px-2.5 py-1.5 text-text focus:border-accent focus:outline-none"
            />
          </label>
          <label className="space-y-1">
            <span className="text-muted block">Max strings</span>
            <input
              type="number"
              min={100}
              max={200000}
              step={100}
              value={maxStrings}
              onChange={(event) => setMaxStrings(Number(event.target.value))}
              className="w-full bg-bg border border-border rounded-input px-2.5 py-1.5 text-text focus:border-accent focus:outline-none"
            />
          </label>
          <label className="space-y-1">
            <span className="text-muted block">Only analyzers (optional)</span>
            <input
              type="text"
              value={only}
              onChange={(event) => setOnly(event.target.value)}
              placeholder="pe.structure, strings.generic"
              className="w-full bg-bg border border-border rounded-input px-2.5 py-1.5 text-text font-mono focus:border-accent focus:outline-none"
            />
          </label>
          <label className="space-y-1">
            <span className="text-muted block">Skip analyzers (optional)</span>
            <input
              type="text"
              value={skip}
              onChange={(event) => setSkip(event.target.value)}
              placeholder="heuristics.generic"
              className="w-full bg-bg border border-border rounded-input px-2.5 py-1.5 text-text font-mono focus:border-accent focus:outline-none"
            />
          </label>
        </div>

        <button
          onClick={() => void startScan()}
          disabled={busy || !file}
          className="w-full px-3 py-2 rounded-input bg-accent/10 hover:bg-accent/20 disabled:opacity-50 text-accent text-xs font-semibold border border-accent/30 flex items-center justify-center space-x-2"
        >
          {busy && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
          <span>{busy ? "Scanning…" : "Start scan"}</span>
        </button>

        {(busy || jobId) && (
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[11px] text-muted">
              <span className="font-mono">{stage || "queued"}</span>
              <span>{Math.round(percent)}%</span>
            </div>
            <div className="h-1.5 rounded-full bg-panel-2 overflow-hidden">
              <div
                className="h-full bg-accent transition-all"
                style={{ width: `${Math.max(2, Math.min(100, percent))}%` }}
              />
            </div>
            {jobId && <p className="text-[10px] text-muted font-mono break-all">job {jobId}</p>}
          </div>
        )}

        {error && (
          <div className="flex items-start space-x-2 p-2.5 rounded-input bg-critical/10 border border-critical/30 text-critical text-xs">
            <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </div>
    </div>
  );
}
