"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { Brand } from "@/components/brand";
import { Icon, type IconName } from "@/components/icons";
import { ThemeToggle } from "@/components/theme-toggle";
import { browserApi } from "@/lib/api";

const mainItems: Array<{ label: string; href: string; icon: IconName }> = [
  { label: "Dashboard", href: "/dashboard", icon: "dashboard" },
  { label: "Scans", href: "/scan", icon: "scan" },
  { label: "Ativos", href: "/assets", icon: "assets" },
  { label: "Vulnerabilidades", href: "/vulnerabilities", icon: "vulnerability" },
  { label: "Remediação", href: "/remediation", icon: "queue" },
  { label: "Relatórios", href: "/reports/monthly", icon: "report" },
];

type UserRole = "administrador" | "gestor" | "analista" | "visualizador";

interface SessionUser {
  id: string;
  name: string;
  email: string;
  client_id: number;
  client_name: string;
  role: UserRole;
}

const roleLabels: Record<UserRole, string> = {
  administrador: "Administrador",
  gestor: "Gestor",
  analista: "Analista",
  visualizador: "Visualizador",
};

interface SidebarProps {
  isExpanded: boolean;
  onToggle: () => void;
}

export function Sidebar({ isExpanded, onToggle }: SidebarProps) {
  const pathname = usePathname();
  const router = useRouter();
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [user, setUser] = useState<SessionUser | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    async function loadSession() {
      try {
        const response = await browserApi("/auth/me", { signal: controller.signal });
        if (response.status === 401) {
          router.replace("/login");
          return;
        }
        if (response.ok) setUser((await response.json()) as SessionUser);
      } catch (sessionError) {
        if (!(sessionError instanceof DOMException && sessionError.name === "AbortError")) {
          setUser(null);
        }
      }
    }
    void loadSession();
    return () => controller.abort();
  }, [router]);

  async function handleLogout() {
    setIsLoggingOut(true);
    try {
      await browserApi("/auth/logout", { method: "POST" });
    } finally {
      router.replace("/login");
      router.refresh();
      setIsLoggingOut(false);
    }
  }

  return (
    <aside className={`sidebar${isExpanded ? "" : " sidebar--collapsed"}`}>
        <div className="sidebar__brand">
          <Brand />
          <span className="sidebar__edition">BY NEOGUARDIAN</span>
        </div>

        <div className="sidebar__nav-control">
          <p className="sidebar__label">Visão geral</p>
          <button
            aria-expanded={isExpanded}
            aria-label={isExpanded ? "Recolher navegação" : "Expandir navegação"}
            className="sidebar__toggle"
            onClick={onToggle}
            type="button"
          >
            <Icon name={isExpanded ? "chevronLeft" : "chevronRight"} size={18} />
          </button>
        </div>
        <nav className="sidebar__nav" aria-label="Navegação principal">
          {[
            ...mainItems,
            ...(user?.role === "administrador"
              ? [{ label: "Acessos", href: "/access", icon: "users" as IconName }]
              : []),
          ].map((item) => {
            const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`);
            return (
              <Link
                aria-label={item.label}
                className={`sidebar__item${isActive ? " sidebar__item--active" : ""}`}
                href={item.href}
                key={item.href}
              >
                <Icon name={item.icon} size={18} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="sidebar__appearance">
          <div className="sidebar__appearance-copy">
            <span>Aparência</span>
            <small>Preferência visual</small>
          </div>
          <ThemeToggle compact />
        </div>

        <div className="sidebar__footer">
          <div className="avatar">{user?.name.slice(0, 1).toLocaleUpperCase("pt-BR") ?? "W"}</div>
          <div className="sidebar__user">
            <strong>{user?.name ?? "Carregando perfil"}</strong>
            <span>{user ? roleLabels[user.role] : "Ambiente seguro"}</span>
          </div>
          <button
            aria-label="Sair da plataforma"
            className="sidebar__logout"
            disabled={isLoggingOut}
            onClick={handleLogout}
            type="button"
          >
            <Icon name="logout" size={17} />
          </button>
        </div>
    </aside>
  );
}
