import React from "react";

/**
 * @file LocatorTable.tsx
 * @brief Formats locator key/value pairs with hex formatting and section annotations.
 */

interface LocatorTableProps {
  locator: Record<string, unknown>;
}

/**
 * @brief Formats raw locator values with hex representation if applicable.
 * @param key Property key.
 * @param val Property value.
 * @return Formatted string representation.
 */
export function formatLocatorValue(key: string, val: unknown): string {
  if (val === null || val === undefined) return "null";
  if (typeof val === "number") {
    // If key suggests an address or offset, display in both decimal and hex
    if (/offset|rva|address|addr|va/i.test(key)) {
      return `${val} (0x${val.toString(16).toUpperCase()})`;
    }
    return val.toString();
  }
  if (typeof val === "boolean") {
    return val ? "true" : "false";
  }
  if (typeof val === "object") {
    return JSON.stringify(val);
  }
  return String(val);
}

/**
 * @brief Key/value table component for evidence locator coordinates.
 */
export function LocatorTable({ locator }: LocatorTableProps) {
  const entries = Object.entries(locator);

  if (entries.length === 0) {
    return <div className="text-xs text-muted">No locator coordinates provided.</div>;
  }

  return (
    <div className="rounded-input border border-border overflow-hidden bg-bg">
      <table className="w-full text-left text-xs border-collapse">
        <tbody>
          {entries.map(([key, val], idx) => (
            <tr
              key={key}
              className={`border-b border-border/50 ${idx % 2 === 0 ? "bg-panel/40" : "bg-bg"}`}
            >
              <td className="py-2 px-3 font-mono text-muted w-1/3 select-none">{key}</td>
              <td className="py-2 px-3 font-mono font-medium text-text break-all">
                {formatLocatorValue(key, val)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
