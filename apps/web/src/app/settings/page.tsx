"use client";

/**
 * @file page.tsx
 * @brief Settings: adapter mode, local API endpoint, health check and cache management.
 */

import React, { useState } from "react";
import { Settings, Trash2, Check, Server, FileText, Wifi, AlertCircle, Loader2 } from "lucide-react";
import { useReport } from "@/lib/report-context";
import { getApiBaseUrl } from "@/lib/data-source";
import type { ApiHealth } from "@/types/api";

/** @brief Workbench settings page. */
export default function SettingsPage() {
  const { mode, setMode, apiHealth, apiError, refreshApiHealth } = useReport();
  const [apiUrl, setApiUrl] = useState(getApiBaseUrl());
  const [selectedMode, setSelectedMode] = useState<"FILE" | "API">(mode);
  const [saved, setSaved] = useState(false);
  const [cleared, setCleared] = useState(false);
  const [testing, setTesting] = useState(false);
  const [probeResult, setProbeResult] = useState<ApiHealth | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);

  const handleSave = (event: React.FormEvent) => {
    event.preventDefault();
    setMode(selectedMode, apiUrl.trim() || getApiBaseUrl());
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2000);
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setProbeError(null);
    setProbeResult(null);
    try {
      const base = (apiUrl.trim() || getApiBaseUrl()).replace(/\/+$/, "");
      const response = await fetch(`${base}/api/health`, { headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const health = (await response.json()) as ApiHealth;
      setProbeResult(health);
      if (selectedMode === "API") await refreshApiHealth();
    } catch (error: unknown) {
      setProbeError(error instanceof Error ? error.message : "connection failed");
    } finally {
      setTesting(false);
    }
  };

  const handleClearCache = () => {
    window.localStorage.removeItem("avero_recent_reports");
    setCleared(true);
    window.setTimeout(() => setCleared(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-text flex items-center space-x-2">
          <Settings className="w-5 h-5 text-accent" />
          <span>Workbench Settings</span>
        </h1>
        <p className="text-xs text-muted">
          Configure the data adapter, local API endpoint and contract pins.
        </p>
      </div>

      <form onSubmit={handleSave} className="space-y-4">
        <div className="p-4 rounded-card bg-panel border border-border space-y-3">
          <span className="text-xs font-semibold text-text uppercase tracking-wider text-[11px] block">
            Data Source Adapter
          </span>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label
              className={`p-3 rounded-card border cursor-pointer flex items-start space-x-3 transition-colors ${
                selectedMode === "FILE"
                  ? "bg-accent/10 border-accent"
                  : "bg-bg border-border hover:bg-panel-2"
              }`}
            >
              <input
                type="radio"
                name="adapterMode"
                value="FILE"
                checked={selectedMode === "FILE"}
                onChange={() => setSelectedMode("FILE")}
                className="mt-1"
              />
              <div className="space-y-1">
                <div className="text-xs font-bold text-text flex items-center space-x-1.5">
                  <FileText className="w-3.5 h-3.5 text-accent" />
                  <span>File Mode (Offline)</span>
                </div>
                <p className="text-[11px] text-muted leading-relaxed">
                  Parse user-dropped report.json files in the browser with zero network access.
                </p>
              </div>
            </label>

            <label
              className={`p-3 rounded-card border cursor-pointer flex items-start space-x-3 transition-colors ${
                selectedMode === "API"
                  ? "bg-accent/10 border-accent"
                  : "bg-bg border-border hover:bg-panel-2"
              }`}
            >
              <input
                type="radio"
                name="adapterMode"
                value="API"
                checked={selectedMode === "API"}
                onChange={() => setSelectedMode("API")}
                className="mt-1"
              />
              <div className="space-y-1">
                <div className="text-xs font-bold text-text flex items-center space-x-1.5">
                  <Server className="w-3.5 h-3.5 text-accent" />
                  <span>API Mode (Local Server)</span>
                </div>
                <p className="text-[11px] text-muted leading-relaxed">
                  Scan artifacts and stream jobs from the local <code className="text-accent">avero serve</code> daemon.
                </p>
              </div>
            </label>
          </div>
        </div>

        <div className="p-4 rounded-card bg-panel border border-border space-y-3">
          <label htmlFor="apiUrlInput" className="text-xs font-semibold text-text uppercase tracking-wider text-[11px] block">
            Local API Endpoint URL
          </label>
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              id="apiUrlInput"
              type="text"
              value={apiUrl}
              onChange={(event) => setApiUrl(event.target.value)}
              placeholder="http://127.0.0.1:8787"
              className="flex-1 bg-bg border border-border text-xs rounded-input px-3 py-2 text-text font-mono focus:border-accent focus:outline-none"
            />
            <button
              type="button"
              onClick={() => void handleTestConnection()}
              disabled={testing}
              className="px-3 py-2 rounded-input bg-panel-2 hover:bg-border text-text text-xs font-medium border border-border flex items-center justify-center space-x-1.5"
            >
              {testing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Wifi className="w-3.5 h-3.5" />}
              <span>{testing ? "Testing…" : "Test connection"}</span>
            </button>
          </div>

          {probeResult && (
            <p className="text-[11px] text-low flex items-center space-x-1.5">
              <Check className="w-3.5 h-3.5" />
              <span>
                {probeResult.api_version} · core {probeResult.core_version} · engines:{" "}
                {Object.entries(probeResult.engines || {})
                  .map(([id, installed]) => `${id}${installed ? "+" : "-"}`)
                  .join(", ") || "n/a"}
              </span>
            </p>
          )}
          {(probeError || apiError) && (
            <p className="text-[11px] text-critical flex items-center space-x-1.5">
              <AlertCircle className="w-3.5 h-3.5" />
              <span>{probeError || apiError}</span>
            </p>
          )}
          {apiHealth && mode === "API" && (
            <p className="text-[11px] text-muted">
              Active API: <span className="font-mono text-text">{apiHealth.api_version}</span>
            </p>
          )}
        </div>

        <button
          type="submit"
          className="px-4 py-2 rounded-input bg-accent hover:bg-accent/90 text-bg text-xs font-semibold flex items-center space-x-1.5 transition-colors"
        >
          {saved ? <Check className="w-4 h-4" /> : null}
          <span>{saved ? "Settings Saved" : "Save Changes"}</span>
        </button>
      </form>

      <div className="p-4 rounded-card bg-panel border border-border space-y-3">
        <span className="text-xs font-semibold text-text uppercase tracking-wider text-[11px] block">
          Cache & Storage Management
        </span>
        <p className="text-xs text-muted">Clear recent report summaries stored in browser storage.</p>
        <button
          onClick={handleClearCache}
          className="px-3 py-1.5 rounded-input bg-critical/10 hover:bg-critical/20 text-critical text-xs font-medium border border-critical/30 flex items-center space-x-1.5 transition-colors"
        >
          {cleared ? <Check className="w-3.5 h-3.5" /> : <Trash2 className="w-3.5 h-3.5" />}
          <span>{cleared ? "Cache Cleared" : "Clear Recent Reports Cache"}</span>
        </button>
      </div>

      <div className="p-4 rounded-card bg-panel border border-border space-y-2 text-xs">
        <span className="font-semibold text-text uppercase tracking-wider text-[11px] block">
          Contract Standards
        </span>
        <div className="grid grid-cols-2 gap-2 text-muted">
          <div>
            Report Schema: <strong className="text-text font-mono">avero.report/v1</strong>
          </div>
          <div>
            API Contract: <strong className="text-text font-mono">avero.api/v1</strong>
          </div>
          <div>
            Architecture: <strong className="text-text">Next.js 15 + React 19</strong>
          </div>
          <div>
            Environment: <strong className="text-text">Read-only & evidence-first</strong>
          </div>
        </div>
      </div>
    </div>
  );
}
