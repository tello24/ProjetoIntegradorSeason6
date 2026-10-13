import type { ReactNode } from "react";

import { ThemeToggle } from "@/components/theme-toggle";

export default function AuthLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <main className="auth-shell">
      <div className="auth-theme-toggle"><ThemeToggle compact /></div>
      {children}
    </main>
  );
}
