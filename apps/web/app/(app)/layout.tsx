"use client";

import type { ReactNode } from "react";
import { useState } from "react";

import { Brand } from "@/components/brand";
import { Sidebar } from "@/components/sidebar";
import { ThemeToggle } from "@/components/theme-toggle";

export default function ProtectedLayout({ children }: Readonly<{ children: ReactNode }>) {
  const [isSidebarExpanded, setIsSidebarExpanded] = useState(true);

  return (
    <div className={`app-shell${isSidebarExpanded ? "" : " app-shell--sidebar-collapsed"}`}>
      <Sidebar
        isExpanded={isSidebarExpanded}
        onToggle={() => setIsSidebarExpanded((expanded) => !expanded)}
      />
      <header className="mobile-header">
        <Brand />
        <ThemeToggle compact />
      </header>
      <main className="app-main">{children}</main>
    </div>
  );
}
