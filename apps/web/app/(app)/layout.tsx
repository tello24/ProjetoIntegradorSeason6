import type { ReactNode } from "react";

import { Brand } from "@/components/brand";
import { Sidebar } from "@/components/sidebar";
import { ThemeToggle } from "@/components/theme-toggle";

export default function ProtectedLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <div className="app-shell">
      <Sidebar />
      <header className="mobile-header">
        <Brand />
        <ThemeToggle compact />
      </header>
      <main className="app-main">{children}</main>
    </div>
  );
}
