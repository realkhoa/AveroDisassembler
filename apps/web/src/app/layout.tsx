import type { Metadata } from "next";
import "./globals.css";
import { ReportProvider } from "@/lib/report-context";
import { AppShell } from "@/components/layout/AppShell";

/**
 * @file layout.tsx
 * @brief Next.js Root Layout for AveroDisassembler Web Workbench.
 */

export const metadata: Metadata = {
  title: "AveroDisassembler — Reverse-Engineering Workbench",
  description: "Evidence-first, static-only reverse-engineering report workbench.",
};

/**
 * @brief Next.js Root Layout component wrapping all child views with ReportProvider and AppShell.
 * @param props React component props containing children.
 * @return React element representing the document root.
 */
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-bg text-text antialiased">
        <ReportProvider>
          <AppShell>{children}</AppShell>
        </ReportProvider>
      </body>
    </html>
  );
}
