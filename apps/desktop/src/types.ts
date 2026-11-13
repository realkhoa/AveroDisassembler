/** Shared report/API types for the Avero desktop workbench. */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Section {
  name: string;
  va: number;
  vsize: number;
  raw_offset: number;
  raw_size: number;
  entropy: number;
  flags: string[];
}

export interface ImportEntry {
  library: string;
  name?: string;
  ordinal?: number;
  iat_rva?: number;
}

export interface ExportEntry {
  name?: string;
  ordinal: number;
  rva: number;
  forwarder?: string;
}

export interface StringEntry {
  offset: number;
  value: string;
  encoding: string;
  section?: string;
}

export interface Evidence {
  id: string;
  producer: { engine: string; version: string };
  kind: string;
  locator: Record<string, unknown>;
  excerpt?: string;
  confidence: number;
  limitations?: string[];
}

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  detail: string;
  evidence_ids: string[];
  confidence: number;
  remediation?: string;
}

export interface Report {
  schema_id: string;
  tool: { name: string; version: string; ir_version: string };
  generated_at: string;
  artifact: {
    ir_version: string;
    id: string;
    path: string;
    size: number;
    kinds: string[];
    architecture?: string;
    bits?: number;
    endianness?: string;
    entropy: number;
    hashes: Record<string, string>;
    sections?: Section[];
    imports?: ImportEntry[];
    exports?: ExportEntry[];
    strings?: StringEntry[];
    metadata?: Record<string, unknown>;
    evidence?: Evidence[];
  };
  findings: Finding[];
  facts?: Record<string, unknown>;
  coverage?: Record<string, string>;
  unknowns?: string[];
  warnings?: string[];
}

export interface Health {
  status: string;
  core_version: string;
  api_version: string;
  engines?: Record<string, boolean>;
}

export interface JobEvent {
  type: "progress" | "done" | "error";
  job_id: string;
  stage?: string;
  percent?: number;
  message?: string;
  report_id?: string;
  error?: { code: string; message: string };
  result?: Record<string, unknown>;
}

export interface Job {
  id: string;
  status: string;
  stage?: string;
  percent?: number;
  error?: { code: string; message: string };
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
}

export interface Instruction {
  address: number;
  bytes_hex?: string;
  mnemonic: string;
  operands?: string;
  size?: number;
  kind?: string;
}

export interface DecompileFile {
  name?: string;
  entry?: string;
  size?: number;
  content: string;
}

export interface DiffResult {
  schema_id: string;
  size_delta: number;
  old: { report_id: string; size: number; findings: number; kinds: string[] };
  new: { report_id: string; size: number; findings: number; kinds: string[] };
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
}

export interface RecentReport {
  id: string;
  name: string;
  size: number;
  kinds: string[];
  severity: string;
  findings: number;
  opened_at: string;
}

export interface CallRef {
  from: number;
  to: number;
  kind: string;
}

export interface FunctionInfo {
  address: number;
  name: string;
  size: number;
  signature?: string | null;
  callrefs: CallRef[];
}

export interface Annotation {
  name?: string;
  comment?: string;
  prototype?: string;
}

export type AnnotationMap = Record<string, Annotation>;