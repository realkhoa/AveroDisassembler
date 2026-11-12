import type { Config } from "tailwindcss";

/**
 * @file tailwind.config.ts
 * @brief Tailwind CSS configuration using Avero design tokens.
 */
const config: Config = {
  darkMode: "class",
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: "var(--bg)",
        panel: "var(--panel)",
        "panel-2": "var(--panel-2)",
        border: "var(--border)",
        text: "var(--text)",
        muted: "var(--muted)",
        accent: "var(--accent)",
        "accent-2": "var(--accent-2)",
        critical: "var(--critical)",
        high: "var(--high)",
        medium: "var(--medium)",
        low: "var(--low)",
        info: "var(--info)",
      },
      fontFamily: {
        mono: ["var(--mono)", "Cascadia Mono", "Consolas", "monospace"],
      },
      borderRadius: {
        card: "10px",
        input: "6px",
        chip: "999px",
      },
    },
  },
  plugins: [],
};

export default config;
