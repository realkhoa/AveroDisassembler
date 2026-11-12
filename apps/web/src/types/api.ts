/**
 * @file api.ts
 * @brief Types for the local `avero serve` REST/SSE API (`avero.api/v1`).
 * @details Mirrors docs/api/openapi.yaml for the M2–M4 UI surfaces.
 */

import type { AveroReport, Finding } from "@/types/report";

export interface ApiHealth {
  status: "ok";
  core_version: string;
  api_version: string;
  engines?: Record<string, boolean>;
}

export interface ScanOptions {
  min_string_len?: number;
  max_strings?: number;
  only?: string;
  skip?: string;
}

export interface JobError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export type JobStatus = "queued" | "running" | "done" | "failed" | "cancelled";

export interface JobSnapshot {
  id: string;
  status: JobStatus;
  stage?: string;
  percent?: number;
  error?: JobError;
  result?: Record<string, unknown>;
}

export interface JobEvent {
  type: "progress" | "done" | "error";
  job_id: string;
  stage?: string;
  percent?: number;
  message?: string;
  report_id?: string;
  error?: JobError;
  result?: Record<string, unknown>;
}

export interface EngineInfo {
  id: string;
  name: string;
  version: string;
  license?: string;
  integration?: string;
  installed: boolean;
  binary?: string | null;
  homepage?: string | null;
}

export interface FindingQuery {
  severity?: string;
  category?: string;
  q?: string;
  min_confidence?: number;
  cursor?: string;
  limit?: number;
}

export interface Instruction {
  address: number;
  bytes_hex?: string;
  mnemonic: string;
  operands?: string;
  size?: number;
  kind?: string;
}

export interface DisassemblyQuery {
  /** Start address: decimal, or hex string like `0x140001000`; omitted = entry0. */
  start?: string;
  limit?: number;
  analyze?: boolean;
}

export interface DisassemblyPage {
  address: string;
  items: Instruction[];
  total: number | null;
  next_cursor: string | null;
}

export type DecompileEngine = "ilspycmd" | "ghidra";

export interface DecompileRequest {
  engine?: DecompileEngine;
  /** .NET type name, or native function name/address. */
  type?: string;
  limit?: number;
}

export interface DecompileFile {
  name?: string;
  path?: string;
  content: string;
  entry?: string;
  size?: number;
}

export interface DecompileResult {
  engine?: string;
  program?: string;
  language?: string;
  image_base?: string;
  files: DecompileFile[];
}

export interface DiffResult {
  schema_id: string;
  old: {
    report_id: string;
    size: number;
    findings: number;
    kinds: string[];
  };
  new: {
    report_id: string;
    size: number;
    findings: number;
    kinds: string[];
  };
  size_delta: number;
  findings: {
    added: Finding[];
    removed: Finding[];
    unchanged: number;
    counts: { added: number; removed: number; unchanged: number };
  };
  sections: { added: string[]; removed: string[] };
  imports: { added: string[]; removed: string[] };
  exports: { added: string[]; removed: string[] };
  signatures: { added: string[]; removed: string[] };
  metadata: { changed: { key: string; old: unknown; new: unknown }[] };
  kinds: { old: string[]; new: string[] };
}

/** API-mode report fetch payload is the same avero.report/v1 document. */
export type ApiReport = AveroReport;
