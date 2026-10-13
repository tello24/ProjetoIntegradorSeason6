"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { Icon } from "@/components/icons";
import { PageTitle } from "@/components/page-title";
import { browserApi, readApiError } from "@/lib/api";

import styles from "./access-workspace.module.css";

type UserRole = "administrador" | "gestor" | "analista" | "visualizador";

interface AccessUser {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  active: boolean;
  created_at: string;
  last_updated_at: string;
  is_current_user: boolean;
}

interface AccessUserList {
  items: AccessUser[];
  total: number;
}

const roles: Array<{
  value: UserRole;
  label: string;
  description: string;
  permissions: string;
}> = [
  {
    value: "administrador",
    label: "Administrador",
    description: "Governa a plataforma e os acessos.",
    permissions: "Configura usuários, importa scans, opera achados e controla novas versões da IA.",
  },
  {
    value: "gestor",
    label: "Gestor",
    description: "Coordena prazos e responsáveis.",
    permissions: "Acompanha indicadores, distribui tarefas, aplica SLA e pode aceitar riscos.",
  },
  {
    value: "analista",
    label: "Analista",
    description: "Executa a operação técnica.",
    permissions: "Importa scans, trata vulnerabilidades, solicita análise da IA e cria tickets.",
  },
  {
    value: "visualizador",
    label: "Visualizador",
    description: "Consulta sem alterar o ambiente.",
    permissions: "Visualiza dashboards, scans, ativos, vulnerabilidades e relatórios.",
  },
];

export function AccessWorkspace() {
  const router = useRouter();
  const [users, setUsers] = useState<AccessUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isCreating, setIsCreating] = useState(false);
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [temporaryPassword, setTemporaryPassword] = useState("");
  const [role, setRole] = useState<UserRole>("analista");
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const loadUsers = useCallback(async (signal?: AbortSignal) => {
    setIsLoading(true);
    try {
      const response = await browserApi("/access/users", { signal });
      if (response.status === 401) {
        router.replace("/login");
        return;
      }
      if (response.status === 403) {
        router.replace("/dashboard");
        return;
      }
      if (!response.ok) throw new Error(await readApiError(response));
      const payload = (await response.json()) as AccessUserList;
      setUsers(payload.items);
      setError(null);
    } catch (loadError) {
      if (loadError instanceof DOMException && loadError.name === "AbortError") return;
      setError(loadError instanceof Error ? loadError.message : "Não foi possível carregar os acessos.");
    } finally {
      if (!signal?.aborted) setIsLoading(false);
    }
  }, [router]);

  useEffect(() => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => void loadUsers(controller.signal), 0);
    return () => {
      window.clearTimeout(timeout);
      controller.abort();
    };
  }, [loadUsers]);

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsCreating(true);
    setError(null);
    setMessage(null);
    try {
      const response = await browserApi("/access/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          email: email.trim(),
          temporary_password: temporaryPassword,
          role,
        }),
      });
      if (!response.ok) throw new Error(await readApiError(response));
      const created = (await response.json()) as AccessUser;
      setName("");
      setEmail("");
      setTemporaryPassword("");
      setRole("analista");
      setShowForm(false);
      setMessage(`Acesso criado para ${created.name}.`);
      await loadUsers();
    } catch (createError) {
      setError(createError instanceof Error ? createError.message : "Não foi possível criar o acesso.");
    } finally {
      setIsCreating(false);
    }
  }

  async function updateUser(user: AccessUser, changes: { role?: UserRole; active?: boolean }) {
    if (changes.active === false && !window.confirm(`Desativar o acesso de ${user.name}?`)) return;
    setUpdatingId(user.id);
    setError(null);
    setMessage(null);
    try {
      const response = await browserApi(`/access/users/${user.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(changes),
      });
      if (!response.ok) throw new Error(await readApiError(response));
      const updated = (await response.json()) as AccessUser;
      setUsers((current) => current.map((item) => item.id === updated.id ? updated : item));
      setMessage(`Acesso de ${updated.name} atualizado.`);
    } catch (updateError) {
      setError(updateError instanceof Error ? updateError.message : "Não foi possível alterar o acesso.");
      await loadUsers();
    } finally {
      setUpdatingId(null);
    }
  }

  return (
    <div className="page-content">
      <PageTitle
        eyebrow="ADMINISTRAÇÃO"
        title="Controle de acessos"
        description="Defina quem administra, coordena, executa ou apenas consulta o ambiente."
        action={
          <button
            className="button button--primary"
            onClick={() => setShowForm((current) => !current)}
            type="button"
          >
            <Icon name="users" size={17} />
            {showForm ? "Fechar cadastro" : "Novo usuário"}
          </button>
        }
      />

      <section className={styles.roleGrid} aria-label="Perfis disponíveis">
        {roles.map((item) => (
          <article className={`${styles.roleCard} ${styles[`role_${item.value}`]}`} key={item.value}>
            <span>{item.label}</span>
            <strong>{item.description}</strong>
            <p>{item.permissions}</p>
          </article>
        ))}
      </section>

      {showForm && (
        <form className={styles.createPanel} onSubmit={createUser}>
          <div className={styles.formHeading}>
            <div>
              <span>NOVO ACESSO</span>
              <strong>Cadastre a credencial inicial</strong>
            </div>
            <small>O usuário poderá entrar imediatamente com os dados informados.</small>
          </div>
          <div className={styles.formGrid}>
            <AccessField label="Nome">
              <input
                autoComplete="off"
                maxLength={120}
                minLength={2}
                onChange={(event) => setName(event.target.value)}
                placeholder="Nome do usuário"
                required
                value={name}
              />
            </AccessField>
            <AccessField label="E-mail">
              <input
                autoComplete="off"
                onChange={(event) => setEmail(event.target.value)}
                placeholder="usuario@empresa.com"
                required
                type="email"
                value={email}
              />
            </AccessField>
            <AccessField label="Senha inicial">
              <input
                autoComplete="new-password"
                minLength={12}
                onChange={(event) => setTemporaryPassword(event.target.value)}
                placeholder="Mínimo de 12 caracteres"
                required
                type="password"
                value={temporaryPassword}
              />
            </AccessField>
            <AccessField label="Perfil">
              <select onChange={(event) => setRole(event.target.value as UserRole)} value={role}>
                {roles.map((item) => (
                  <option key={item.value} value={item.value}>{item.label}</option>
                ))}
              </select>
            </AccessField>
          </div>
          <div className={styles.formActions}>
            <button className="button button--primary" disabled={isCreating} type="submit">
              {isCreating ? "Criando..." : "Criar acesso"}
            </button>
            <button
              className="button button--secondary"
              onClick={() => setShowForm(false)}
              type="button"
            >
              Cancelar
            </button>
          </div>
        </form>
      )}

      {error && <p className="page-error" role="alert">{error}</p>}
      {message && <p className={styles.success} role="status">{message}</p>}

      <section className={styles.userPanel}>
        <div className={styles.panelHeading}>
          <div>
            <span>EQUIPE DO AMBIENTE</span>
            <strong>{users.length} {users.length === 1 ? "usuário" : "usuários"}</strong>
          </div>
          <small>Alterações de perfil e acesso ficam registradas na auditoria.</small>
        </div>

        <div className={styles.userList}>
          {users.map((user) => (
            <article className={`${styles.userRow} ${!user.active ? styles.userInactive : ""}`} key={user.id}>
              <div className={styles.avatar}>{user.name.slice(0, 1).toLocaleUpperCase("pt-BR")}</div>
              <div className={styles.identity}>
                <strong>
                  {user.name}
                  {user.is_current_user && <small>VOCÊ</small>}
                </strong>
                <span>{user.email}</span>
              </div>
              <label className={styles.roleSelect}>
                <span>PERFIL</span>
                <select
                  disabled={user.is_current_user || updatingId === user.id}
                  onChange={(event) => void updateUser(user, { role: event.target.value as UserRole })}
                  value={user.role}
                >
                  {roles.map((item) => (
                    <option key={item.value} value={item.value}>{item.label}</option>
                  ))}
                </select>
              </label>
              <div className={styles.accessState}>
                <span className={user.active ? styles.activeBadge : styles.inactiveBadge}>
                  {user.active ? "Ativo" : "Desativado"}
                </span>
                <small>Desde {formatDate(user.created_at)}</small>
              </div>
              <button
                className={user.active ? styles.deactivateButton : styles.activateButton}
                disabled={user.is_current_user || updatingId === user.id}
                onClick={() => void updateUser(user, { active: !user.active })}
                type="button"
              >
                {updatingId === user.id
                  ? "Salvando..."
                  : user.active ? "Desativar" : "Reativar"}
              </button>
            </article>
          ))}
          {isLoading && <p className="table-loading">Carregando acessos...</p>}
        </div>
      </section>
    </div>
  );
}

function AccessField({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <label className={styles.field}>
      <span>{label}</span>
      {children}
    </label>
  );
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeZone: "America/Sao_Paulo",
  }).format(new Date(value));
}
