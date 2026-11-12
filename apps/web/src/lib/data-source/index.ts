/**
 * @file index.ts
 * @brief Data-source factory: File mode (M1) or local API mode (M2+).
 */

import { ApiDataSource } from "./api-data-source";
import { FileDataSource } from "./file-data-source";
import type { AveroDataSource } from "./types";

export type AdapterMode = "FILE" | "API";

export const MODE_STORAGE_KEY = "avero_adapter_mode";
export const API_URL_STORAGE_KEY = "avero_api_url";
export const DEFAULT_API_URL = "http://127.0.0.1:8787";
export const MODE_CHANGED_EVENT = "avero-mode-changed";

let cachedSource: { mode: AdapterMode; baseUrl: string; source: AveroDataSource } | null = null;

/** @brief Reads the persisted adapter mode (defaults to FILE). */
export function getAdapterMode(): AdapterMode {
  if (typeof window === "undefined") return "FILE";
  return window.localStorage.getItem(MODE_STORAGE_KEY) === "API" ? "API" : "FILE";
}

/** @brief Reads the persisted API base URL. */
export function getApiBaseUrl(): string {
  if (typeof window === "undefined") return DEFAULT_API_URL;
  return window.localStorage.getItem(API_URL_STORAGE_KEY) || DEFAULT_API_URL;
}

/** @brief Persists adapter settings and notifies same-tab listeners. */
export function setAdapterSettings(mode: AdapterMode, apiUrl?: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(MODE_STORAGE_KEY, mode);
  if (apiUrl) window.localStorage.setItem(API_URL_STORAGE_KEY, apiUrl);
  cachedSource = null;
  window.dispatchEvent(new CustomEvent(MODE_CHANGED_EVENT, { detail: { mode, apiUrl } }));
}

/** @brief Clears the cached data source (e.g. after API URL changes). */
export function resetDataSource(): void {
  cachedSource = null;
}

/** @brief Returns the active data source for the persisted mode. */
export function getDataSource(): AveroDataSource {
  const mode = getAdapterMode();
  const baseUrl = getApiBaseUrl();
  if (!cachedSource || cachedSource.mode !== mode || cachedSource.baseUrl !== baseUrl) {
    cachedSource = {
      mode,
      baseUrl,
      source: mode === "API" ? new ApiDataSource(baseUrl) : new FileDataSource(),
    };
  }
  return cachedSource.source;
}

/** @brief Overrides the active data source instance (tests/advanced use). */
export function setDataSource(source: AveroDataSource): void {
  const mode = getAdapterMode();
  cachedSource = { mode, baseUrl: getApiBaseUrl(), source };
}

export * from "./types";
export * from "./file-data-source";
export * from "./api-data-source";
