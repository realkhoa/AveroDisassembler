"use client";

/**
 * @file report-context.tsx
 * @brief React context for the active report, adapter mode and API health.
 */

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import type { AveroReport } from "@/types/report";
import type { ApiHealth } from "@/types/api";
import {
  getAdapterMode,
  getApiBaseUrl,
  getDataSource,
  MODE_CHANGED_EVENT,
  resetDataSource,
  setAdapterSettings,
  type AdapterMode,
  type AveroDataSource,
} from "@/lib/data-source";
import sampleReportData from "../../../../docs/api/sample-report.json";

interface ReportContextType {
  activeReport: AveroReport | null;
  setActiveReport: (report: AveroReport | null) => void;
  loadReportById: (reportId: string) => Promise<AveroReport | null>;
  loadSampleReport: () => Promise<AveroReport>;
  mode: AdapterMode;
  setMode: (mode: AdapterMode, apiUrl?: string) => void;
  source: AveroDataSource;
  apiHealth: ApiHealth | null;
  apiError: string | null;
  refreshApiHealth: () => Promise<ApiHealth | null>;
}

const ReportContext = createContext<ReportContextType | undefined>(undefined);

/**
 * @brief Provider wrapping components that consume active report and adapter state.
 */
export function ReportProvider({ children }: { children: ReactNode }) {
  const [activeReport, setActiveReport] = useState<AveroReport | null>(null);
  const [mode, setModeState] = useState<AdapterMode>("FILE");
  const [apiHealth, setApiHealth] = useState<ApiHealth | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [source, setSource] = useState<AveroDataSource>(() => getDataSource());

  const refreshApiHealth = useCallback(async (): Promise<ApiHealth | null> => {
    const dataSource = getDataSource();
    if (!dataSource.health) {
      setApiHealth(null);
      return null;
    }
    try {
      const health = await dataSource.health();
      setApiHealth(health);
      setApiError(null);
      return health;
    } catch (error: unknown) {
      setApiHealth(null);
      setApiError(error instanceof Error ? error.message : "API unreachable");
      return null;
    }
  }, []);

  useEffect(() => {
    setModeState(getAdapterMode());
    setSource(getDataSource());

    const onModeChanged = () => {
      resetDataSource();
      const nextSource = getDataSource();
      setModeState(getAdapterMode());
      setSource(nextSource);
      if (getAdapterMode() === "API") {
        void refreshApiHealth();
      } else {
        setApiHealth(null);
        setApiError(null);
      }
    };
    window.addEventListener(MODE_CHANGED_EVENT, onModeChanged);

    if (getAdapterMode() === "API") {
      void refreshApiHealth();
    } else {
      // Keep the bundled sample available in file mode.
      getDataSource()
        .loadReport(JSON.stringify(sampleReportData))
        .catch(() => {
          // Already loaded.
        });
    }

    return () => window.removeEventListener(MODE_CHANGED_EVENT, onModeChanged);
  }, [refreshApiHealth]);

  /**
   * @brief Switches adapter mode and persists the optional API URL.
   */
  const setMode = (nextMode: AdapterMode, apiUrl?: string) => {
    setAdapterSettings(nextMode, apiUrl || getApiBaseUrl());
    setModeState(nextMode);
    resetDataSource();
    const nextSource = getDataSource();
    setSource(nextSource);
    if (nextMode === "API") {
      void refreshApiHealth();
    } else {
      setApiHealth(null);
      setApiError(null);
    }
  };

  const loadReportById = async (reportId: string): Promise<AveroReport | null> => {
    try {
      const dataSource = getDataSource();
      const report = await dataSource.getReport(reportId);
      setActiveReport(report);
      return report;
    } catch {
      // Deep links to the bundled sample report work in file mode even in a fresh
      // browser profile (no prior drop / recent report).
      if (getAdapterMode() === "FILE" && reportId === sampleReportData.artifact.id) {
        try {
          const dataSource = getDataSource();
          const sample = await dataSource.loadReport(JSON.stringify(sampleReportData));
          setActiveReport(sample);
          return sample;
        } catch {
          return null;
        }
      }
      return null;
    }
  };

  const loadSampleReport = async (): Promise<AveroReport> => {
    const dataSource = getDataSource();
    const report = await dataSource.loadReport(JSON.stringify(sampleReportData));
    setActiveReport(report);
    return report;
  };

  return (
    <ReportContext.Provider
      value={{
        activeReport,
        setActiveReport,
        loadReportById,
        loadSampleReport,
        mode,
        setMode,
        source,
        apiHealth,
        apiError,
        refreshApiHealth,
      }}
    >
      {children}
    </ReportContext.Provider>
  );
}

/** @brief Hook for accessing the active report context. */
export function useReport(): ReportContextType {
  const context = useContext(ReportContext);
  if (!context) {
    throw new Error("useReport must be used within a ReportProvider");
  }
  return context;
}
