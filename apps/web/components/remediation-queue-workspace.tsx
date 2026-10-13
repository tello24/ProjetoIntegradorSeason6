"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { EmptyState } from "@/components/empty-state";
import { Icon } from "@/components/icons";
import { PageTitle } from "@/components/page-title";
import {
  statusLabel,
  workflowBadgeClass,
  type WorkflowAssignee,
  type WorkflowStatus,
} from "@/components/vulnerability-workflow";
import { browserApi, readApiError } from "@/lib/api";

import styles from "./remediation-queue-workspace.module.css";

type Severity = "critical" | "high" | "medium" | "low" | "info";
type Priority = "act_now" | "prioritize" | "plan" | "monitor";
type QueueFocus =
  | "all"
  | "act_now"
  | "overdue"
  | "due_soon"
  | "unassigned"
  | "reopened"
  | "quick_wins";
type QueueReason =
  | "overdue"
  | "reopened"
  | "act_now"
  | "unassigned"
  | "due_soon"
  | "prioritized";

interface QueueItem {
  id: number;
  workflow_id: string;
  plugin_id: number;
  severity: Severity;
  title: string;
  asset: string;
  status: WorkflowStatus;
  assignee_id: string | null;
  assignee_name: string | null;
  due_date: string | null;
  effective_due_date: string;
  due_source: "manual" | "sla";
  sla_days: number;
  age_days: number;
  neo_score: number;
  priority: Priority;
  reason: QueueReason;
  occurrence_count: number;
  cves: string[];
  first_detected_at: string;
  last_detected_at: string;
}

interface QueueSummary {
  total_active: number;
  act_now: number;
  overdue: number;
  due_soon: number;
  unassigned: number;
  reopened: number;
  quick_wins: number;
}

interface QueueResponse {
  items: QueueItem[];
  total: number;
  limit: number;
  offset: number;
  can_edit: boolean;
  can_accept_risk: boolean;
  summary: QueueSummary;
}

interface EditDraft {
  status: WorkflowStatus;
  assigneeId: string;
  dueDate: string;
}

const PAGE_SIZE = 25;

const focusOptions: Array<{
  value: QueueFocus;
  label: string;
  summaryKey: keyof QueueSummary;
}> = [
  { value: "all", label: "Fila completa", summaryKey: "total_active" },
  { value: "act_now", label: "Agir agora", summaryKey: "act_now" },
  { value: "overdue", label: "Em atraso", summaryKey: "overdue" },
  { value: "due_soon", label: "Vencem em 7 dias", summaryKey: "due_soon" },
  { value: "unassigned", label: "Sem responsável", summaryKey: "unassigned" },
  { value: "reopened", label: "Reabertas", summaryKey: "reopened" },
  { value: "quick_wins", label: "Quick wins", summaryKey: "quick_wins" },
];

const editableStatuses: Array<{ value: WorkflowStatus; label: string }> = [
  { value: "open", label: "Aberta" },
  { value: "triage", label: "Em triagem" },
  { value: "in_progress", label: "Em correção" },
  { value: "validation", label: "Aguardando validação" },
  { value: "accepted_risk", label: "Risco aceito" },
  { value: "reopened", label: "Reaberta" },
];

const emptySummary: QueueSummary = {
  total_active: 0,
  act_now: 0,
  overdue: 0,
  due_soon: 0,
  unassigned: 0,
  reopened: 0,
  quick_wins: 0,
};

export function RemediationQueueWorkspace() {
  const router = useRouter();
  const [focus, setFocus] = useState<QueueFocus>("all");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [assigneeFilter, setAssigneeFilter] = useState("all");
  const [items, setItems] = useState<QueueItem[]>([]);
  const [summary, setSummary] = useState<QueueSummary>(emptySummary);
  const [assignees, setAssignees] = useState<WorkflowAssignee[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [canEdit, setCanEdit] = useState(false);
  const [canAcceptRisk, setCanAcceptRisk] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [draft, setDraft] = useState<EditDraft | null>(null);
  const [savingId, setSavingId] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const loadQueue = useCallback(async (signal?: AbortSignal) => {
    setIsLoading(true);
    const params = new URLSearchParams({
      focus,
      limit: String(PAGE_SIZE),
      offset: String((page - 1) * PAGE_SIZE),
    });
    if (search.trim()) params.set("search", search.trim());
    if (severity !== "all") params.set("severity", severity);
    if (status !== "all") params.set("status", status);
    if (assigneeFilter !== "all") params.set("assignee_id", assigneeFilter);

    try {
      const response = await browserApi(`/vulnerabilities/queue?${params}`, { signal });
      if (response.status === 401) {
        router.replace("/login");
        return;
      }
      if (!response.ok) throw new Error(await readApiError(response));
      const payload = (await response.json()) as QueueResponse;
      setItems(payload.items);
      setSummary(payload.summary);
      setTotal(payload.total);
      setCanEdit(payload.can_edit);
      setCanAcceptRisk(payload.can_accept_risk);
      setError(null);
    } catch (loadError) {
      if (loadError instanceof DOMException && loadError.name === "AbortError") return;
      setError(loadError instanceof Error ? loadError.message : "Não foi possível carregar a fila.");
    } finally {
      if (!signal?.aborted) setIsLoading(false);
    }
  }, [assigneeFilter, focus, page, router, search, severity, status]);

  useEffect(() => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => void loadQueue(controller.signal), 220);
    return () => {
      window.clearTimeout(timeout);
      controller.abort();
    };
  }, [loadQueue]);

  useEffect(() => {
    const controller = new AbortController();
    async function loadAssignees() {
      try {
        const response = await browserApi("/vulnerabilities/assignees", {
          signal: controller.signal,
        });
        if (response.status === 401) {
          router.replace("/login");
          return;
        }
        if (!response.ok) throw new Error(await readApiError(response));
        setAssignees((await response.json()) as WorkflowAssignee[]);
      } catch (loadError) {
        if (loadError instanceof DOMException && loadError.name === "AbortError") return;
        setError(loadError instanceof Error ? loadError.message : "Não foi possível carregar a equipe.");
      }
    }
    void loadAssignees();
    return () => controller.abort();
  }, [router]);

  function selectFocus(value: QueueFocus) {
    setFocus(value);
    setPage(1);
  }

  function openEditor(item: QueueItem) {
    setEditingId(item.id);
    setDraft({
      status: item.status,
      assigneeId: item.assignee_id ?? "",
      dueDate: item.due_date ?? "",
    });
    setMessage(null);
    setError(null);
  }

  async function updateItem(
    item: QueueItem,
    changes: Partial<EditDraft>,
    successMessage: string,
  ) {
    const nextStatus = changes.status ?? item.status;
    const nextAssignee = changes.assigneeId === undefined
      ? item.assignee_id
      : changes.assigneeId || null;
    const nextDueDate = changes.dueDate === undefined
      ? item.due_date
      : changes.dueDate || null;

    setSavingId(item.id);
    setMessage(null);
    setError(null);
    try {
      const response = await browserApi(`/vulnerabilities/${item.id}/workflow`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: nextStatus,
          assignee_id: nextAssignee,
          due_date: nextDueDate,
          note: "Atualização realizada pela fila de remediação.",
        }),
      });
      if (response.status === 401) {
        router.replace("/login");
        return;
      }
      if (!response.ok) throw new Error(await readApiError(response));
      setEditingId(null);
      setDraft(null);
      setMessage(successMessage);
      await loadQueue();
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : "Não foi possível atualizar a tarefa.");
    } finally {
      setSavingId(null);
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="page-content">
      <PageTitle
        eyebrow="OPERAÇÃO DE SEGURANÇA"
        title="Fila de remediação"
        description="O que precisa de ação agora, ordenado por prazo, recorrência e WVM Score."
      />

      <section className={styles.intro}>
        <div>
          <span>POLÍTICA DE SLA</span>
          <strong>Crítica 7d · Alta 15d · Média 30d · Baixa 60d</strong>
          <p>Quando não há prazo manual, o WVM sugere automaticamente uma data sem alterar o registro.</p>
        </div>
        <div className={styles.introCallout}>
          <Icon name="info" size={17} />
          <span>O prazo só vira definitivo quando alguém aplica o SLA ou salva a tarefa.</span>
        </div>
      </section>

      <nav className={styles.focusGrid} aria-label="Prioridades da fila">
        {focusOptions.map((option) => (
          <button
            aria-current={focus === option.value ? "page" : undefined}
            className={`${styles.focusCard} ${styles[`focus_${option.value}`]} ${
              focus === option.value ? styles.focusActive : ""
            }`}
            key={option.value}
            onClick={() => selectFocus(option.value)}
            type="button"
          >
            <strong>{summary[option.summaryKey]}</strong>
            <span>{option.label}</span>
          </button>
        ))}
      </nav>

      <section className={styles.filters} aria-label="Filtros da fila">
        <div className="search-field">
          <Icon name="search" size={18} />
          <input
            aria-label="Pesquisar na fila"
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
            placeholder="Pesquisar CVE, vulnerabilidade ou ativo..."
            type="search"
            value={search}
          />
        </div>
        <QueueSelect
          label="Severidade"
          onChange={(value) => { setSeverity(value); setPage(1); }}
          value={severity}
        >
          <option value="all">Todas as severidades</option>
          <option value="critical">Crítica</option>
          <option value="high">Alta</option>
          <option value="medium">Média</option>
          <option value="low">Baixa</option>
        </QueueSelect>
        <QueueSelect
          label="Status"
          onChange={(value) => { setStatus(value); setPage(1); }}
          value={status}
        >
          <option value="all">Todos os status</option>
          {editableStatuses.filter((option) => option.value !== "accepted_risk").map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </QueueSelect>
        <QueueSelect
          label="Responsável"
          onChange={(value) => { setAssigneeFilter(value); setPage(1); }}
          value={assigneeFilter}
        >
          <option value="all">Toda a equipe</option>
          {assignees.map((assignee) => (
            <option key={assignee.id} value={assignee.id}>{assignee.name}</option>
          ))}
        </QueueSelect>
      </section>

      {error && <p className="page-error" role="alert">{error}</p>}
      {message && <p className={styles.success} role="status">{message}</p>}

      <section className={styles.queue} aria-label="Tarefas de remediação">
        <div className={styles.queueHeader}>
          <div>
            <span>FILA PRIORIZADA</span>
            <strong>{total} {total === 1 ? "tarefa" : "tarefas"}</strong>
          </div>
          <small>A ordem combina atraso, reabertura, score, responsável e prazo.</small>
        </div>

        <div className={styles.queueList}>
          {items.map((item, index) => (
            <article className={styles.queueItem} key={item.workflow_id}>
              <div className={styles.rank} aria-label={`Posição ${(page - 1) * PAGE_SIZE + index + 1}`}>
                {String((page - 1) * PAGE_SIZE + index + 1).padStart(2, "0")}
              </div>
              <div className={styles.itemMain}>
                <div className={styles.itemHeading}>
                  <div>
                    <div className={styles.badges}>
                      <SeverityBadge severity={item.severity} />
                      <ReasonBadge reason={item.reason} />
                      {item.occurrence_count > 1 && (
                        <span className={styles.quickWin}>
                          {item.occurrence_count} ocorrências · mesma correção
                        </span>
                      )}
                    </div>
                    <Link href={`/vulnerabilities/${item.id}`}>{item.title}</Link>
                    <small>
                      {item.asset} · {item.cves.slice(0, 2).join(" · ") || `Plugin ${item.plugin_id}`}
                    </small>
                  </div>
                  <span className={`neo-badge neo-badge--${item.priority}`}>
                    <strong>{item.neo_score}</strong>
                    <small>WVM</small>
                  </span>
                </div>

                <div className={styles.operationalGrid}>
                  <OperationalFact label="Etapa">
                    <span className={workflowBadgeClass(item.status)}>{statusLabel(item.status)}</span>
                  </OperationalFact>
                  <OperationalFact label="Responsável">
                    <strong className={!item.assignee_name ? styles.missing : ""}>
                      {item.assignee_name ?? "Sem responsável"}
                    </strong>
                  </OperationalFact>
                  <OperationalFact label={item.due_source === "manual" ? "Prazo definido" : "SLA sugerido"}>
                    <strong className={item.reason === "overdue" ? styles.overdue : ""}>
                      {formatCalendarDate(item.effective_due_date)}
                    </strong>
                  </OperationalFact>
                  <OperationalFact label="Exposição">
                    <strong>{item.age_days} {item.age_days === 1 ? "dia" : "dias"}</strong>
                  </OperationalFact>
                </div>

                {editingId === item.id && draft && (
                  <div className={styles.editor}>
                    <QueueSelect
                      label="Nova etapa"
                      onChange={(value) => setDraft({ ...draft, status: value as WorkflowStatus })}
                      value={draft.status}
                    >
                      {editableStatuses
                        .filter((option) => option.value !== "accepted_risk" || canAcceptRisk)
                        .map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                        ))}
                    </QueueSelect>
                    <QueueSelect
                      label="Responsável"
                      onChange={(value) => setDraft({ ...draft, assigneeId: value })}
                      value={draft.assigneeId}
                    >
                      <option value="">Sem responsável</option>
                      {assignees.map((assignee) => (
                        <option key={assignee.id} value={assignee.id}>{assignee.name}</option>
                      ))}
                    </QueueSelect>
                    <label className={styles.editorField}>
                      <span>Prazo</span>
                      <input
                        onChange={(event) => setDraft({ ...draft, dueDate: event.target.value })}
                        type="date"
                        value={draft.dueDate}
                      />
                    </label>
                    <div className={styles.editorActions}>
                      <button
                        className="button button--primary"
                        disabled={savingId === item.id}
                        onClick={() => void updateItem(item, draft, "Tarefa atualizada na fila.")}
                        type="button"
                      >
                        {savingId === item.id ? "Salvando..." : "Salvar"}
                      </button>
                      <button
                        className="button button--secondary"
                        onClick={() => { setEditingId(null); setDraft(null); }}
                        type="button"
                      >
                        Cancelar
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <div className={styles.itemActions}>
                {canEdit && ["open", "triage", "reopened"].includes(item.status) && (
                  <button
                    className="button button--primary"
                    disabled={savingId === item.id}
                    onClick={() => void updateItem(
                      item,
                      { status: "in_progress" },
                      "Correção iniciada.",
                    )}
                    type="button"
                  >
                    Iniciar correção
                  </button>
                )}
                {canEdit && item.due_source === "sla" && (
                  <button
                    className="button button--secondary"
                    disabled={savingId === item.id}
                    onClick={() => void updateItem(
                      item,
                      { dueDate: item.effective_due_date },
                      `SLA de ${item.sla_days} dias aplicado.`,
                    )}
                    type="button"
                  >
                    Aplicar SLA
                  </button>
                )}
                {canEdit && (
                  <button
                    className={styles.editButton}
                    disabled={savingId === item.id}
                    onClick={() => openEditor(item)}
                    type="button"
                  >
                    Editar tarefa
                  </button>
                )}
                <Link className={styles.detailLink} href={`/vulnerabilities/${item.id}`}>
                  Ver detalhes →
                </Link>
              </div>
            </article>
          ))}

          {!isLoading && items.length === 0 && (
            <EmptyState
              description="Ajuste os filtros ou importe um novo scan para alimentar a operação."
              icon={<Icon name="queue" size={27} />}
              title="Nenhuma tarefa nesta visão"
            />
          )}
          {isLoading && <p className="table-loading">Priorizando tarefas...</p>}
        </div>

        {totalPages > 1 && (
          <div className={styles.pagination}>
            <button
              className="button button--secondary"
              disabled={page === 1}
              onClick={() => setPage((current) => Math.max(1, current - 1))}
              type="button"
            >
              Anterior
            </button>
            <span>Página {page} de {totalPages}</span>
            <button
              className="button button--secondary"
              disabled={page === totalPages}
              onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
              type="button"
            >
              Próxima
            </button>
          </div>
        )}
      </section>
    </div>
  );
}

function QueueSelect({
  children,
  label,
  onChange,
  value,
}: {
  children: React.ReactNode;
  label: string;
  onChange: (value: string) => void;
  value: string;
}) {
  return (
    <label className={styles.selectField}>
      <span>{label}</span>
      <select onChange={(event) => onChange(event.target.value)} value={value}>
        {children}
      </select>
    </label>
  );
}

function OperationalFact({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <div className={styles.operationalFact}>
      <span>{label}</span>
      {children}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const labels: Record<Severity, string> = {
    critical: "Crítica",
    high: "Alta",
    medium: "Média",
    low: "Baixa",
    info: "Informativa",
  };
  return <span className={`severity-badge severity-badge--${severity}`}>{labels[severity]}</span>;
}

function ReasonBadge({ reason }: { reason: QueueReason }) {
  const labels: Record<QueueReason, string> = {
    overdue: "Em atraso",
    reopened: "Reaberta",
    act_now: "Agir agora",
    unassigned: "Sem responsável",
    due_soon: "Prazo próximo",
    prioritized: "Priorizada",
  };
  return <span className={`${styles.reasonBadge} ${styles[`reason_${reason}`]}`}>{labels[reason]}</span>;
}

function formatCalendarDate(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeZone: "UTC",
  }).format(new Date(value));
}
