"use client";

/**
 * @file page.tsx
 * @brief Engine pack manager (/engines): installed engines and install jobs (M3).
 */

import React, { useCallback, useEffect, useRef, useState } from "react";
import { Package, RefreshCw, Download, CheckCircle2, Server, AlertCircle, Loader2 } from "lucide-react";
import { useReport } from "@/lib/report-context";
import type { EngineInfo, JobEvent } from "@/types/api";

/** @brief Engine manager page. */
export default function EnginesPage() {
  const { mode, source, apiHealth, refreshApiHealth } = useReport();
  const [engines, setEngines] = useState<EngineInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [jobStage, setJobStage] = useState<string | null>(null);
  const [jobPercent, setJobPercent] = useState(0);
  const [busyEngine, setBusyEngine] = useState<string | null>(null);
  const unsubscribeRef = useRef<(() => void) | null>(null);

  const loadEngines = useCallback(async () => {
    if (!source.getEngines) return;
    setLoading(true);
    setError(null);
    try {
      setEngines(await source.getEngines());
    } catch (loadError: unknown) {
      setError(loadError instanceof Error ? loadError.message : "Failed to load engines");
    } finally {
      setLoading(false);
    }
  }, [source]);

  useEffect(() => {
    if (mode === "API") {
      void refreshApiHealth();
      void loadEngines();
    }
    return () => unsubscribeRef.current?.();
  }, [mode, refreshApiHealth, loadEngines]);

  const install = async (engine: EngineInfo) => {
    if (!source.installEngine) return;
    if (!window.confirm(`Install ${engine.name} ${engine.version}? This downloads the engine pack.`)) {
      return;
    }
    setBusyEngine(engine.id);
    setError(null);
    setJobStage("queued");
    setJobPercent(0);
    try {
      const job = await source.installEngine(engine.id);
      const onEvent = (event: JobEvent) => {
        if (event.type === "progress") {
          setJobStage(event.stage || "installing");
          setJobPercent(event.percent || 0);
          return;
        }
        setBusyEngine(null);
        setJobStage(null);
        if (event.type === "error") {
          setError(event.error?.message || "Engine install failed");
        } else {
          void loadEngines();
        }
      };
      if (source.subscribeJob) {
        unsubscribeRef.current = source.subscribeJob(job.job_id, onEvent);
      } else {
        setBusyEngine(null);
        setJobStage(null);
      }
    } catch (installError: unknown) {
      setBusyEngine(null);
      setJobStage(null);
      setError(installError instanceof Error ? installError.message : "Engine install failed");
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-text flex items-center space-x-2">
            <Package className="w-5 h-5 text-accent" />
            <span>Engine Packs</span>
          </h1>
          <p className="text-xs text-muted">
            Sidecar engines installed by the Avero core (no engine code is linked into the binary).
          </p>
        </div>
        <button
          onClick={() => void loadEngines()}
          disabled={mode !== "API" || loading}
          className="px-3 py-1.5 rounded-input bg-panel-2 hover:bg-border disabled:opacity-50 text-text text-xs font-medium border border-border flex items-center space-x-1.5"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {mode !== "API" ? (
        <div className="p-4 rounded-card bg-panel border border-border space-y-2">
          <div className="flex items-center space-x-2 text-high text-sm font-semibold">
            <Server className="w-4 h-4" />
            <span>Engine management requires API mode</span>
          </div>
          <p className="text-xs text-muted">
            Switch to API mode in Settings and start <code className="text-accent">avero serve</code>.
            In file mode, manage engines with the CLI:
          </p>
          <pre className="text-[11px] text-text bg-bg border border-border rounded-input p-3 overflow-x-auto">
{`avero engine list
avero engine doctor
avero engine install ilspycmd
avero engine install ghidra`}
          </pre>
        </div>
      ) : !apiHealth ? (
        <div className="p-4 rounded-card bg-panel border border-border space-y-2">
          <div className="flex items-center space-x-2 text-critical text-sm font-semibold">
            <AlertCircle className="w-4 h-4" />
            <span>API offline</span>
          </div>
          <button
            onClick={() => void refreshApiHealth()}
            className="px-3 py-1.5 rounded-input bg-accent/10 hover:bg-accent/20 text-accent text-xs font-semibold border border-accent/30"
          >
            Retry connection
          </button>
        </div>
      ) : (
        <div className="rounded-card bg-panel border border-border overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-panel-2 text-muted uppercase tracking-wider text-[11px]">
              <tr>
                <th className="text-left px-4 py-2.5">Engine</th>
                <th className="text-left px-4 py-2.5">Version</th>
                <th className="text-left px-4 py-2.5">License</th>
                <th className="text-left px-4 py-2.5">Integration</th>
                <th className="text-left px-4 py-2.5">Status</th>
                <th className="text-right px-4 py-2.5">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {engines.map((engine) => (
                <tr key={engine.id} className="hover:bg-panel-2/50">
                  <td className="px-4 py-2.5">
                    <div className="font-semibold text-text">{engine.name}</div>
                    <div className="text-[10px] text-muted font-mono">{engine.id}</div>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-text">{engine.version}</td>
                  <td className="px-4 py-2.5 text-muted">{engine.license || "n/a"}</td>
                  <td className="px-4 py-2.5 text-muted">{engine.integration || "sidecar"}</td>
                  <td className="px-4 py-2.5">
                    {engine.installed ? (
                      <span className="inline-flex items-center space-x-1 text-low">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>installed</span>
                      </span>
                    ) : (
                      <span className="text-muted">not installed</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    {!engine.installed ? (
                      <button
                        onClick={() => void install(engine)}
                        disabled={busyEngine !== null}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-input bg-accent/10 hover:bg-accent/20 disabled:opacity-50 text-accent text-[11px] font-semibold border border-accent/30"
                      >
                        {busyEngine === engine.id ? (
                          <Loader2 className="w-3 h-3 animate-spin" />
                        ) : (
                          <Download className="w-3 h-3" />
                        )}
                        <span>Install</span>
                      </button>
                    ) : (
                      <span className="text-[11px] text-muted font-mono">
                        {engine.binary?.split(/[/\\]/).pop() || "ready"}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
              {engines.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-muted">
                    No engines reported by the API.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {jobStage && (
        <div className="space-y-1">
          <div className="flex items-center justify-between text-[11px] text-muted">
            <span className="font-mono">{jobStage}</span>
            <span>{Math.round(jobPercent)}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-panel-2 overflow-hidden">
            <div className="h-full bg-accent transition-all" style={{ width: `${jobPercent}%` }} />
          </div>
        </div>
      )}

      {error && (
        <div className="flex items-start space-x-2 p-3 rounded-input bg-critical/10 border border-critical/30 text-critical text-xs">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}
