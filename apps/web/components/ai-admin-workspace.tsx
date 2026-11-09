"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { PageTitle } from "@/components/page-title";
import { browserApi } from "@/lib/api";

import styles from "./ai-admin-workspace.module.css";

interface Usage {
  analyses: number;
  input_tokens: number;
  output_tokens: number;
  estimated_cost_usd: number;
}

interface Summary {
  configuration: {
    provider: "disabled" | "anthropic" | "openai";
    state: "disabled" | "missing_key" | "configured";
    key_configured: boolean;
    workspace_configured: boolean;
    model: string | null;
    prompt_version: string;
    timeout_seconds: number;
    max_output_tokens: number;
    input_price_per_million_usd: number | null;
    output_price_per_million_usd: number | null;
  };
  days: number;
  period_start: string;
  as_of: string;
  usage: Usage;
  last_success_at: string | null;
  failures: number;
  failures_unknown_cost: number;
  configuration_blocks: number;
  models: (Usage & { provider: string; model: string })[];
  recent_failures: {
    id: number;
    occurred_at: string;
    provider: "disabled" | "anthropic" | "openai";
    error_code: string;
    guidance: string;
    cost_status: "unknown" | "not_requested";
  }[];
}

const providers: Record<string, string> = { anthropic: "Anthropic / Claude", openai: "OpenAI", disabled: "Desativada" };
const states = { configured: "Configurada · conexão não testada", missing_key: "Configuração incompleta", disabled: "IA desativada" };
const number = (value: number) => value.toLocaleString("pt-BR");
const usd = (value: number) => new Intl.NumberFormat("pt-BR", {
  style: "currency", currency: "USD", minimumFractionDigits: 6, maximumFractionDigits: 8,
}).format(value);
const date = (value: string | null) => value ? new Intl.DateTimeFormat("pt-BR", {
  dateStyle: "short", timeStyle: "short", timeZone: "America/Sao_Paulo",
}).format(new Date(value)) : "Nenhuma análise salva";

export function AIAdminWorkspace() {
  const router = useRouter();
  const [days, setDays] = useState("30");
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoading(true);
      setData(null);
      setError(null);
      // A bounded, read-only request. No automatic retries or generation action.
      const timeout = window.setTimeout(() => controller.abort("timeout"), 15000);
      try {
        const response = await browserApi(`/admin/ai/summary?days=${days}`, {
          signal: controller.signal, cache: "no-store",
        });
        if (response.status === 401 || response.status === 403) {
          router.replace(response.status === 401 ? "/login" : "/dashboard");
          return;
        }
        if (!response.ok) throw new Error("A API não conseguiu carregar o painel. Tente atualizar os dados.");
        const payload = await response.json() as Summary;
        if (!controller.signal.aborted) setData(payload);
      } catch (failure) {
        if (controller.signal.aborted && controller.signal.reason !== "timeout") return;
        setError(controller.signal.reason === "timeout"
          ? "A consulta demorou mais que o esperado. Confira a API e tente novamente."
          : failure instanceof Error ? failure.message : "Não foi possível consultar a API.");
      } finally {
        window.clearTimeout(timeout);
        if (!controller.signal.aborted || controller.signal.reason === "timeout") setLoading(false);
      }
    }
    const start = window.setTimeout(() => void load(), 0);
    return () => { window.clearTimeout(start); controller.abort(); };
  }, [days, refresh, router]);

  return (
    <div className={`page-content ${styles.workspace}`}>
      <PageTitle eyebrow="Administração" title="Administração da IA"
        description="Configuração e histórico local. Consultar este painel não consome tokens."
        action={<button className="button button--primary" type="button" disabled={loading}
          onClick={() => setRefresh((value) => value + 1)}>Atualizar dados</button>} />

      <div className={styles.toolbar}>
        <label>Período do consumo
          <select value={days} onChange={(event) => setDays(event.target.value)} disabled={loading}>
            <option value="7">Últimos 7 dias</option>
            <option value="30">Últimos 30 dias</option>
            <option value="90">Últimos 90 dias</option>
          </select>
        </label>
        <span>{data ? `${date(data.period_start)} a ${date(data.as_of)} · Brasília` : "Somente leitura · acesso administrativo"}</span>
      </div>
      {loading && <p role="status">Consultando registros locais…</p>}
      {error && <p role="alert" className={styles.notice}>{error}</p>}
      {data && <>
        <section className={styles.panel} aria-labelledby="ai-config-title">
          <div className={styles.heading}>
            <h2 id="ai-config-title">Configuração atual</h2>
            <span className={styles.badge}>{states[data.configuration.state]}</span>
          </div>
          <dl className={styles.config}>
            <div><dt>Provedor</dt><dd>{providers[data.configuration.provider]}</dd></div>
            <div><dt>Modelo</dt><dd>{data.configuration.model ?? "Não selecionado"}</dd></div>
            <div><dt>Chave da API</dt><dd>{data.configuration.key_configured ? "Preenchida · valor protegido" : "Não configurada para o provedor ativo"}</dd></div>
            <div><dt>Versão do prompt</dt><dd>{data.configuration.prompt_version}</dd></div>
            <div><dt>Limite de saída por geração</dt><dd>{number(data.configuration.max_output_tokens)} tokens</dd></div>
            <div><dt>Tempo limite</dt><dd>{data.configuration.timeout_seconds} segundos</dd></div>
            {data.configuration.provider === "anthropic" && <div><dt>Workspace</dt><dd>{data.configuration.workspace_configured ? "Identificador preenchido" : "Não informado · pode não ser necessário"}</dd></div>}
            <div><dt>Última análise salva · todo o histórico</dt><dd>{date(data.last_success_at)}{data.last_success_at && " · Brasília"}</dd></div>
          </dl>
          <p className={styles.note}>A validade da chave, o saldo e a disponibilidade do provedor não foram testados.
            Alterações de configuração são feitas no .env pelo responsável técnico e exigem recriar a API.</p>
        </section>

        <section className={styles.metrics} aria-label="Consumo local da IA">
          <article><span>Análises salvas no período</span><strong>{number(data.usage.analyses)}</strong><small>Inclui novas versões, mesmo substituídas.</small></article>
          <article><span>Tokens das análises salvas</span><strong>{number(data.usage.input_tokens + data.usage.output_tokens)}</strong><small>{number(data.usage.input_tokens)} de entrada · {number(data.usage.output_tokens)} de saída</small></article>
          <article><span>Custo conhecido estimado</span><strong>{usd(data.usage.estimated_cost_usd)}</strong><small>Somente análises salvas. Não é a fatura.</small></article>
          <article><span>Tentativas com custo desconhecido</span><strong>{number(data.failures_unknown_cost)}</strong><small>O provedor pode ter processado tokens.</small></article>
        </section>

        <p className={styles.notice}>O valor acima não inclui tentativas com custo desconhecido nem uso fora desta instalação.
          Confira a cobrança oficial no provedor. Respostas salvas são reutilizadas sem nova geração;
          não medimos acessos ao cache nem estimamos uma economia fictícia.</p>

        <section className={styles.panel} aria-labelledby="ai-models-title">
          <h2 id="ai-models-title">Consumo por modelo</h2>
          {data.models.length ? <div className={styles.tableScroll}><table aria-label="Consumo por modelo">
            <thead><tr><th>Provedor / modelo</th><th>Análises</th><th>Entrada</th><th>Saída</th><th>Custo estimado</th></tr></thead>
            <tbody>{data.models.map((item) => <tr key={`${item.provider}:${item.model}`}>
              <td>{providers[item.provider] ?? item.provider}<small>{item.model}</small></td>
              <td>{number(item.analyses)}</td><td>{number(item.input_tokens)}</td><td>{number(item.output_tokens)}</td><td>{usd(item.estimated_cost_usd)}</td>
            </tr>)}</tbody>
          </table></div> : <p className={styles.note}>Nenhuma análise salva neste período. Isso não comprova ausência de cobranças no provedor.</p>}
          {data.configuration.input_price_per_million_usd !== null && <p className={styles.note}>
            Tarifas atuais configuradas por milhão de tokens: entrada {usd(data.configuration.input_price_per_million_usd)};
            saída {usd(data.configuration.output_price_per_million_usd ?? 0)}. São valores do .env, não preços consultados ao vivo.
            Custos históricos não são recalculados ao trocar a tarifa.
          </p>}
        </section>

        <section className={styles.panel} aria-labelledby="ai-failures-title">
          <h2 id="ai-failures-title">Falhas e bloqueios recentes</h2>
          <p className={styles.note}>{number(data.failures)} registros no período · {number(data.configuration_blocks)} bloqueios sem chamada externa.
            Exibimos até 20 registros. O histórico de falhas começa com esta atualização; falhas antigas não são recuperadas dos logs.</p>
          {data.recent_failures.length ? <ul className={styles.failures}>
            {data.recent_failures.map((item) => <li key={item.id}>
              <div className={styles.heading}><strong>{item.error_code}</strong><span>{date(item.occurred_at)} · Brasília</span></div>
              <p>{item.guidance}</p>
              <small>{providers[item.provider]} · {item.cost_status === "unknown" ? "Custo não confirmado" : "Nenhuma chamada externa"}</small>
            </li>)}
          </ul> : <p className={styles.note}>Nenhuma falha registrada neste período. Não é uma confirmação de que a conexão funciona agora.</p>}
        </section>
      </>}
    </div>
  );
}
