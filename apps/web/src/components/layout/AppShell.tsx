"use client";

/**
 * @file AppShell.tsx
 * @brief Master application container orchestrating header, sidebar, body, and status bar.
 */

import React, { type ReactNode } from "react";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { StatusBar } from "./StatusBar";

/**
 * @brief Main layout shell wrapping all screen views.
 * @param props React children nodes.
 */
export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-bg text-text">
      <Header />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto bg-bg p-4 md:p-6">{children}</main>
      </div>
      <StatusBar />
    </div>
  );
}
