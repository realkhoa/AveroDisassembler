/** Local function annotations (renames/comments/prototypes) keyed by artifact + address. */

import type { Annotation, AnnotationMap, FunctionInfo } from "./types";

const KEY_PREFIX = "avero_annotations_";

export function loadAnnotations(reportId: string): AnnotationMap {
  try {
    return JSON.parse(localStorage.getItem(`${KEY_PREFIX}${reportId}`) || "{}") as AnnotationMap;
  } catch {
    return {};
  }
}

export function saveAnnotations(reportId: string, annotations: AnnotationMap): void {
  try {
    localStorage.setItem(`${KEY_PREFIX}${reportId}`, JSON.stringify(annotations));
  } catch {
    /* ignore quota */
  }
}

export function annotationFor(annotations: AnnotationMap, address: number): Annotation | undefined {
  return annotations[String(address)];
}

export function displayName(
  annotations: AnnotationMap,
  address: number,
  fallback: string,
): string {
  return annotationFor(annotations, address)?.name?.trim() || fallback;
}

export function functionAt(
  functions: FunctionInfo[],
  address: number,
): FunctionInfo | undefined {
  return functions.find(
    (fn) => address >= fn.address && address < fn.address + Math.max(fn.size, 1),
  );
}
