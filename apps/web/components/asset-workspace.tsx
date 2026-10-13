"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { EmptyState } from "@/components/empty-state";
import { Icon } from "@/components/icons";
import { MetricCard } from "@/components/metric-card";
import { PageTitle } from "@/components/page-title";

import styles from "./asset-workspace.module.css";

type Priority = "act_now" | "prioritize" | "plan" | "monitor";
type BusinessEnvironment =
  | "producao"
  | "homologacao"
  | "desenvolvimento"
  | "laboratorio"
  | "corporativo"
  | "outro";
type BusinessCriticality = "critica" | "alta" | "media" | "baixa";

export interface AssetItem {
  id: number;
  name: string;
  address: string;
  fqdn: string | null;
  operating_system: string | null;
  credentialed: boolean;
  vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  risk_score: number;
  priority: Priority;
  last_seen: string;
  environment: BusinessEnvironment | null;
  business_criticality: BusinessCriticality | null;
  business_owner_name: string | null;
  responsible_team: string | null;
  business_service: string | null;
  internet_exposed: boolean | null;
}

export interface AssetListResponse {
  items: AssetItem[];
  summary: {
    total: number;
    critical_exposure: number;
    credentialed: number;
    uncredentialed: number;
    clean: number;
    critical_business_assets: number;
    critical_business_exposure: number;
    production_uncredentialed: number;
    without_owner: number;
  };
}

interface AssetWorkspaceProps {
  initialData: AssetListResponse;
}

export function AssetWorkspace({ initialData }: AssetWorkspaceProps) {
  const [search, setSearch] = useState("");
  const [exposure, setExposure] = useState("all");
  const [coverage, setCoverage] = useState("all");
  const [operatingSystem, setOperatingSystem] = useState("all");
  const [environment, setEnvironment] = useState("all");
  const [criticality, setCriticality] = useState("all");

  const systems = useMemo(
    () => Array.from(
      new Set(initialData.items.map((item) => item.operating_system).filter(Boolean)),
    ).sort((left, right) => left!.localeCompare(right!, "pt-BR")) as string[],
    [initialData.items],
  );

  const filteredItems = useMemo(() => {
    const normalizedSearch = search.trim().toLocaleLowerCase("pt-BR");
    return initialData.items.filter((item) => {
      const matchesSearch = !normalizedSearch || [
        item.name,
        item.address,
        item.fqdn,
        item.operating_system,
        item.business_owner_name,
        item.responsible_team,
        item.business_service,
      ].some((value) => value?.toLocaleLowerCase("pt-BR").includes(normalizedSearch));
      const matchesCoverage = coverage === "all"
        || (coverage === "credentialed" && item.credentialed)
        || (coverage === "uncredentialed" && !item.credentialed);
      const matchesSystem = operatingSystem === "all"
        || item.operating_system === operatingSystem;
      const matchesExposure = exposure === "all"
        || (exposure === "critical" && item.critical > 0)
        || (exposure === "high" && item.critical === 0 && item.high > 0)
        || (exposure === "attention" && item.vulnerabilities > 0
          && item.critical === 0 && item.high === 0)
        || (exposure === "clean" && item.vulnerabilities === 0);
      const matchesEnvironment = environment === "all" || item.environment === environment;
      const matchesCriticality = criticality === "all"
        || item.business_criticality === criticality
        || (criticality === "undefined" && item.business_criticality === null);
      return matchesSearch && matchesCoverage && matchesSystem && matchesExposure
        && matchesEnvironment && matchesCriticality;
    });
  }, [coverage, criticality, environment, exposure, initialData.items, operatingSystem, search]);

  const credentialCoverage = initialData.summary.total === 0
    ? 0
    : Math.round((initialData.summary.credentialed / initialData.summary.total) * 100);
  const highestRisk = initialData.items.reduce(
    (current, item) => Math.max(current, item.risk_score),
    0,
  );
  const filtersActive = search || exposure !== "all" || coverage !== "all"
    || operatingSystem !== "all" || environment !== "all" || criticality !== "all";

  return (
    <div className="page-content">
      <PageTitle
        eyebrow="SUPERFÍCIE MONITORADA"
        title="Inventário de ativos"
        description={`${initialData.summary.total} ${initialData.summary.total === 1 ? "ativo identificado" : "ativos identificados"} nos scans atuais.`}
        action={
          <span className="status-pill">
            <i /> Atualizado pelo último scan
          </span>
        }
      />

      <section className="metrics-grid" aria-label="Indicadores do inventário">
        <MetricCard
          helper="Presentes nos escopos mais recentes"
          icon={<Icon name="assets" size={19} />}
          label="ATIVOS MONITORADOS"
          tone="cyan"
          value={initialData.summary.total}
        />
        <MetricCard
          helper="Com ao menos um achado crítico"
          icon={<Icon name="vulnerability" size={19} />}
          label="EXPOSIÇÃO CRÍTICA"
          tone="red"
          value={initialData.summary.critical_exposure}
        />
        <MetricCard
          helper={`${initialData.summary.credentialed} de ${initialData.summary.total} ativos`}
          icon={<Icon name="shield" size={19} />}
          label="COBERTURA CREDENCIADA"
          tone="green"
          value={`${credentialCoverage}%`}
        />
        <MetricCard
          helper="Maior WVM Score ativo encontrado"
          icon={<Icon name="shield" size={19} />}
          label="MAIOR RISCO"
          tone="blue"
          value={highestRisk}
        />
      </section>

      <section className={styles.contextSignals} aria-label="Sinais de contexto do negócio">
        <ContextSignal
          helper={`${initialData.summary.critical_business_assets} ativos classificados como críticos`}
          label="CRÍTICOS COM EXPOSIÇÃO"
          tone="danger"
          value={initialData.summary.critical_business_exposure}
        />
        <ContextSignal
          helper="Produção com visibilidade técnica limitada"
          label="PRODUÇÃO SEM CREDENCIAL"
          tone="warning"
          value={initialData.summary.production_uncredentialed}
        />
        <ContextSignal
          helper="Precisam de definição de ownership"
          label="ATIVOS SEM RESPONSÁVEL"
          value={initialData.summary.without_owner}
        />
      </section>

      <section className={styles.filters} aria-label="Filtros de ativos">
        <div className={styles.searchField}>
          <Icon name="search" size={18} />
          <input
            aria-label="Pesquisar ativos"
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Pesquisar hostname, IP ou sistema..."
            type="search"
            value={search}
          />
        </div>
        <label className={styles.selectField}>
          <span className="sr-only">Exposição</span>
          <select onChange={(event) => setExposure(event.target.value)} value={exposure}>
            <option value="all">Todas as exposições</option>
            <option value="critical">Com vulnerabilidade crítica</option>
            <option value="high">Com vulnerabilidade alta</option>
            <option value="attention">Média ou baixa</option>
            <option value="clean">Sem vulnerabilidades</option>
          </select>
        </label>
        <label className={styles.selectField}>
          <span className="sr-only">Cobertura do scan</span>
          <select onChange={(event) => setCoverage(event.target.value)} value={coverage}>
            <option value="all">Qualquer cobertura</option>
            <option value="credentialed">Scan credenciado</option>
            <option value="uncredentialed">Scan não credenciado</option>
          </select>
        </label>
        <label className={styles.selectField}>
          <span className="sr-only">Sistema operacional</span>
          <select
            onChange={(event) => setOperatingSystem(event.target.value)}
            value={operatingSystem}
          >
            <option value="all">Todos os sistemas</option>
            {systems.map((system) => <option key={system} value={system}>{system}</option>)}
          </select>
        </label>
        <label className={styles.selectField}>
          <span className="sr-only">Ambiente de negócio</span>
          <select onChange={(event) => setEnvironment(event.target.value)} value={environment}>
            <option value="all">Todos os ambientes</option>
            <option value="producao">Produção</option>
            <option value="homologacao">Homologação</option>
            <option value="desenvolvimento">Desenvolvimento</option>
            <option value="laboratorio">Laboratório</option>
            <option value="corporativo">Corporativo</option>
            <option value="outro">Outro</option>
          </select>
        </label>
        <label className={styles.selectField}>
          <span className="sr-only">Criticidade de negócio</span>
          <select onChange={(event) => setCriticality(event.target.value)} value={criticality}>
            <option value="all">Todas as criticidades</option>
            <option value="critica">Crítica</option>
            <option value="alta">Alta</option>
            <option value="media">Média</option>
            <option value="baixa">Baixa</option>
            <option value="undefined">Não definida</option>
          </select>
        </label>
      </section>

      <section className={`panel ${styles.tablePanel}`}>
        <div className={styles.tableScroll}>
          <div className={styles.table} role="table" aria-label="Inventário de ativos">
            <div className={styles.tableHeader} role="row">
              <span role="columnheader">ATIVO</span>
              <span role="columnheader">SISTEMA</span>
              <span role="columnheader">NEGÓCIO</span>
              <span role="columnheader">COBERTURA</span>
              <span role="columnheader">VULNS</span>
              <span role="columnheader">CRÍTICAS / ALTAS</span>
              <span role="columnheader">RISCO</span>
              <span role="columnheader">ÚLTIMA VISÃO</span>
            </div>
            {filteredItems.map((item) => (
              <Link
                aria-label={`Abrir detalhes do ativo ${item.name}`}
                className={styles.tableRow}
                href={`/assets/${item.id}`}
                key={item.id}
                role="row"
              >
                <span className={styles.identity} role="cell">
                  <strong>{item.name}</strong>
                  <small>{item.address}</small>
                </span>
                <span className={styles.operatingSystem} role="cell">
                  {item.operating_system ?? "Não identificado"}
                </span>
                <span className={styles.businessContext} role="cell">
                  <strong>{environmentLabel(item.environment)}</strong>
                  <small>{criticalityLabel(item.business_criticality)}</small>
                </span>
                <span role="cell">
                  <CoverageBadge credentialed={item.credentialed} />
                </span>
                <strong className={styles.vulnerabilityCount} role="cell">
                  {item.vulnerabilities}
                </strong>
                <span className={styles.severityCounts} role="cell">
                  <strong>{item.critical}</strong>
                  <i />
                  <span>{item.high}</span>
                </span>
                <span role="cell">
                  <RiskBadge
                    clean={item.vulnerabilities === 0}
                    priority={item.priority}
                    score={item.risk_score}
                  />
                </span>
                <span className={styles.lastSeen} role="cell">
                  {formatDate(item.last_seen)}
                </span>
              </Link>
            ))}
          </div>
        </div>
        {filteredItems.length === 0 && (
          <EmptyState
            description={filtersActive
              ? "Ajuste os filtros para ampliar a busca no inventário."
              : "Importe um arquivo .nessus para identificar os ativos monitorados."}
            icon={<Icon name="assets" size={26} />}
            title={filtersActive ? "Nenhum ativo corresponde aos filtros" : "Inventário vazio"}
          />
        )}
        {filteredItems.length > 0 && (
          <footer className={styles.tableFooter}>
            Mostrando {filteredItems.length} de {initialData.summary.total} ativos
          </footer>
        )}
      </section>
    </div>
  );
}

function ContextSignal({
  label,
  value,
  helper,
  tone,
}: {
  label: string;
  value: number;
  helper: string;
  tone?: "danger" | "warning";
}) {
  return (
    <article className={`${styles.contextSignal} ${tone ? styles[`contextSignal_${tone}`] : ""}`}>
      <strong>{value}</strong>
      <span>{label}</span>
      <small>{helper}</small>
    </article>
  );
}

function CoverageBadge({ credentialed }: { credentialed: boolean }) {
  return (
    <span className={credentialed ? styles.coverageGood : styles.coverageWarning}>
      <i /> {credentialed ? "Credenciado" : "Não credenciado"}
    </span>
  );
}

function RiskBadge({
  clean,
  priority,
  score,
}: {
  clean: boolean;
  priority: Priority;
  score: number;
}) {
  const labels: Record<Priority, string> = {
    act_now: "Agir agora",
    prioritize: "Priorizar",
    plan: "Planejar",
    monitor: "Monitorar",
  };
  return (
    <span className={`${styles.risk} ${styles[`risk_${priority}`]}`}>
      <strong>{score}</strong>
      <small>{clean ? "Sem achados" : labels[priority]}</small>
    </span>
  );
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeZone: "America/Sao_Paulo",
  }).format(new Date(value));
}

function environmentLabel(value: BusinessEnvironment | null) {
  if (value === null) return "Sem ambiente";
  return {
    producao: "Produção",
    homologacao: "Homologação",
    desenvolvimento: "Desenvolvimento",
    laboratorio: "Laboratório",
    corporativo: "Corporativo",
    outro: "Outro",
  }[value];
}

function criticalityLabel(value: BusinessCriticality | null) {
  if (value === null) return "Criticidade não definida";
  return {
    critica: "Criticidade crítica",
    alta: "Criticidade alta",
    media: "Criticidade média",
    baixa: "Criticidade baixa",
  }[value];
}
