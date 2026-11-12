import React from "react";

/**
 * @file EntropyBar.tsx
 * @brief Visual 0–8 scale entropy meter with packing/encryption threshold warnings.
 */

interface EntropyBarProps {
  entropy: number;
}

/**
 * @brief Clamps and determines color tone for Shannon entropy values (0.0 to 8.0).
 * @param val Raw entropy value.
 * @return Color class name.
 */
export function getEntropyTone(val: number): {
  barClass: string;
  textClass: string;
  tag: string;
} {
  const clamped = Math.max(0, Math.min(8, val));
  if (clamped >= 7.2) {
    return { barClass: "bg-critical", textClass: "text-critical", tag: "Encrypted/Packed" };
  }
  if (clamped >= 6.8) {
    return { barClass: "bg-high", textClass: "text-high", tag: "High Entropy" };
  }
  if (clamped >= 4.5) {
    return { barClass: "bg-medium", textClass: "text-medium", tag: "Code/Data" };
  }
  return { barClass: "bg-low", textClass: "text-low", tag: "Sparse" };
}

/**
 * @brief 0–8 entropy progress meter component.
 */
export function EntropyBar({ entropy }: EntropyBarProps) {
  const clamped = Math.max(0, Math.min(8, entropy));
  const percent = (clamped / 8) * 100;
  const tone = getEntropyTone(entropy);

  return (
    <div className="flex items-center space-x-2">
      <div className="w-24 h-2 rounded-chip bg-bg border border-border overflow-hidden">
        <div
          style={{ width: `${percent}%` }}
          className={`h-full ${tone.barClass} transition-all`}
        />
      </div>
      <span className={`font-mono text-xs font-semibold ${tone.textClass}`}>
        {clamped.toFixed(3)}
      </span>
    </div>
  );
}
