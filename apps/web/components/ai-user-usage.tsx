"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { browserApi } from "@/lib/api";
import { type AIUsage, formatAICost as usd, formatAIDate as date, formatAITokens as number } from "@/lib/ai-usage";

import styles from "./ai-admin-workspace.module.css";

export interface AIUserUsageData extends AIUsage {
  user_id: string | null;
  name: string;
  active: boolean;
  vulnerabilities: number;
  failures_unknown_cost: number;
  configuration_blocks: number;
}

interface VulnerabilityUsage extends AIUsage {
  workflow_id: string;
  finding_id: number | null;
  plugin_id: number | null;
  title: string;
  asset: string | null;
  protocol: string | null;
  port: number | null;
  last_generated_at: string;
}

interface Detail {
  page: number;
  page_size: number;
  total: number;
  items: VulnerabilityUsage[];
}

export function AIUserUsagePanel({ users, days, asOf }: {
  users: AIUserUsageData[];
  days: number;
  asOf: string;
}) {
  const [selected, setSelected] = useState<AIUserUsageData | null>(null);
  return <section className={styles.panel} aria-labelledby="ai-users-title">
    <h2 id="ai-users-title">Consumo por pessoa</h2>
    <p className={styles.note}>Do maior para o menor custo estimado das análises salvas.
      O consumo pertence a quem solicitou a geração, não ao responsável atual pela correção.
      Novas versões entram na conta; consultar uma resposta salva não gera novo consumo.</p>
    {users.length ? <div className={styles.tableScroll}><table aria-label="Consumo por pessoa">
      <thead><tr><th>Pessoa</th><th>Gerações / vulnerabilidades</th><th>Tokens</th><th>Custo estimado</th><th>Detalhes</th></tr></thead>
      <tbody>{users.map((user) => <tr key={user.user_id ?? "unattributed"}
        className={selected?.user_id === user.user_id && selected ? styles.selectedRow : undefined}>
        <td><strong>{user.name}</strong>{!user.active && user.user_id && <small>Conta inativa ou sem vínculo atual</small>}
          {user.failures_unknown_cost > 0 && <small className={styles.unknownCost}>
            {number(user.failures_unknown_cost)} tentativa(s) com custo desconhecido
          </small>}
          {user.configuration_blocks > 0 && <small>{number(user.configuration_blocks)} bloqueio(s) sem chamada externa</small>}
        </td>
        <td>{number(user.analyses)} gerações<small>{number(user.vulnerabilities)} vulnerabilidade(s)</small></td>
        <td>{number(user.input_tokens + user.output_tokens)}<small>{number(user.input_tokens)} entrada · {number(user.output_tokens)} saída</small></td>
        <td>{user.analyses ? usd(user.estimated_cost_usd) : "Nenhum custo registrado"}
          {user.failures_unknown_cost > 0 && <small>Falhas não incluídas neste valor</small>}</td>
        <td><button type="button" className={styles.detailButton}
          aria-label={`Ver vulnerabilidades de ${user.name}`}
          aria-expanded={selected !== null && selected.user_id === user.user_id}
          aria-controls={selected !== null && selected.user_id === user.user_id ? "ai-user-detail" : undefined}
          onClick={() => setSelected(selected !== null && selected.user_id === user.user_id ? null : user)}>
          {selected !== null && selected.user_id === user.user_id ? "Ocultar" : "Ver vulnerabilidades"}
        </button></td>
      </tr>)}</tbody>
    </table></div> : <p className={styles.note}>Nenhuma atividade de IA registrada para pessoas neste período.</p>}
    {selected && <UserVulnerabilities key={selected.user_id ?? "unattributed"}
      user={selected} days={days} asOf={asOf} />}
  </section>;
}

function UserVulnerabilities({ user, days, asOf }: {
  user: AIUserUsageData; days: number; asOf: string;
}) {
  const router = useRouter();
  const [page, setPage] = useState(1);
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState<Detail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoading(true); setData(null); setError(null);
      const timeout = window.setTimeout(() => controller.abort("timeout"), 15000);
      try {
        const query = new URLSearchParams({ days: String(days), as_of: asOf, page: String(page) });
        const response = await browserApi(`/admin/ai/users/${user.user_id ?? "unattributed"}/vulnerabilities?${query}`, {
          signal: controller.signal, cache: "no-store",
        });
        if (response.status === 401 || response.status === 403) {
          router.replace(response.status === 401 ? "/login" : "/dashboard");
          return;
        }
        if (!response.ok) throw new Error("Não foi possível consultar as vulnerabilidades desta pessoa.");
        const payload = await response.json() as Detail;
        if (!controller.signal.aborted) setData(payload);
      } catch (failure) {
        if (controller.signal.aborted && controller.signal.reason !== "timeout") return;
        setError(controller.signal.reason === "timeout" ? "A consulta demorou mais que o esperado."
          : failure instanceof Error ? failure.message : "Não foi possível consultar a API.");
      } finally {
        window.clearTimeout(timeout);
        if (!controller.signal.aborted || controller.signal.reason === "timeout") setLoading(false);
      }
    }
    const start = window.setTimeout(() => void load(), 0);
    return () => { window.clearTimeout(start); controller.abort(); };
  }, [user.user_id, days, asOf, page, refresh, router]);

  return <section id="ai-user-detail" className={styles.userDetail} aria-labelledby="ai-user-detail-title">
    <h3 id="ai-user-detail-title">Vulnerabilidades · {user.name}</h3>
    <p className={styles.note}>Somente gerações salvas no período selecionado, somando todas as versões por vulnerabilidade.
      As tentativas com custo desconhecido não entram nos valores abaixo.</p>
    {loading && <p role="status">Consultando vulnerabilidades…</p>}
    {error && <div><p role="alert" className={styles.notice}>{error}</p>
      <button type="button" className={styles.detailButton} onClick={() => setRefresh((value) => value + 1)}>Tentar consultar novamente</button></div>}
    {data && <>
      {data.items.length ? <div className={styles.tableScroll}><table aria-label={`Vulnerabilidades de ${user.name}`}>
        <thead><tr><th>Vulnerabilidade / ativo</th><th>Gerações</th><th>Tokens</th><th>Custo estimado</th><th>Última geração</th></tr></thead>
        <tbody>{data.items.map((item) => <tr key={item.workflow_id}>
          <td>{item.finding_id !== null ? <Link prefetch={false} href={`/vulnerabilities/${item.finding_id}`}>{item.title}</Link> : <strong>{item.title}</strong>}
            <small>{item.asset ?? "Ativo indisponível"} · {item.protocol ?? "—"}/{item.port ?? "—"} · Plugin {item.plugin_id ?? "—"}</small>
            {item.finding_id === null && <small>Sem ocorrência disponível; histórico de consumo preservado.</small>}</td>
          <td>{number(item.analyses)}</td>
          <td>{number(item.input_tokens + item.output_tokens)}<small>{number(item.input_tokens)} entrada · {number(item.output_tokens)} saída</small></td>
          <td>{usd(item.estimated_cost_usd)}</td><td>{date(item.last_generated_at)}<small>Brasília</small></td>
        </tr>)}</tbody>
      </table></div> : <p className={styles.note}>Nenhuma análise salva para esta pessoa neste período.</p>}
      <div className={styles.pagination}>
        <span>{number(data.total)} vulnerabilidade(s) · Página {data.page} de {Math.max(1, Math.ceil(data.total / data.page_size))}</span>
        <div><button type="button" className={styles.detailButton} disabled={loading || data.page <= 1} onClick={() => setPage(page - 1)}>Página anterior</button>
          <button type="button" className={styles.detailButton} disabled={loading || data.page * data.page_size >= data.total} onClick={() => setPage(page + 1)}>Próxima página</button></div>
      </div>
    </>}
  </section>;
}
