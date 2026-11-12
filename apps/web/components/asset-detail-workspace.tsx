"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";

import { EmptyState } from "@/components/empty-state";
import { Icon } from "@/components/icons";
import { PageTitle } from "@/components/page-title";
import styles from "@/app/(app)/assets/[id]/asset-detail.module.css";
import { browserApi, readApiError } from "@/lib/api";

type Priority = "act_now" | "prioritize" | "plan" | "monitor";
type Severity = "critical" | "high" | "medium" | "low" | "info";
type WorkflowStatus =
  | "open"
  | "triage"
  | "in_progress"
  | "validation"
  | "accepted_risk"
  | "resolved"
  | "reopened";
type BusinessEnvironment =
  | "producao"
  | "homologacao"
  | "desenvolvimento"
  | "laboratorio"
  | "corporativo"
  | "outro";
type BusinessCriticality = "critica" | "alta" | "media" | "baixa";
type AssetTab =
  | "overview"
  | "business"
  | "network"
  | "vulnerabilities"
  | "history"
  | "evidence";

interface ServiceReference {
  protocol: string;
  port: number;
  service: string | null;
}

export interface AssetDetail {
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
  facts: {
    netbios: string | null;
    mac: string | null;
    system_type: string | null;
    bios_uuid: string | null;
    cpes: string[];
    operating_system_confidence: number | null;
    operating_system_method: string | null;
  };
  coverage: {
    credentialed: boolean;
    local_checks_protocol: string | null;
    scan_started_at: string | null;
    scan_ended_at: string | null;
    duration_seconds: number | null;
    last_authenticated_results_at: string | null;
    last_unauthenticated_results_at: string | null;
    policy_used: string | null;
  };
  inventory: {
    first_seen: string;
    last_seen: string;
    scans_observed: number;
    observed_services: number;
    services_with_findings: number;
    patch_summary_total_cves: number | null;
  };
  changes: {
    available: boolean;
    previous_scan_name: string | null;
    previous_scan_at: string | null;
    new_findings: number;
    corrected_findings: number;
    persistent_findings: number;
    reopened_findings: number;
    vulnerability_delta: number;
    risk_delta: number;
    ports_added: ServiceReference[];
    ports_removed: ServiceReference[];
    operating_system_changed: boolean;
    credentialed_changed: boolean;
  };
  business_context: AssetBusinessContext;
  services: Array<{
    protocol: string;
    port: number;
    service: string | null;
    vulnerabilities: number;
    highest_severity: Severity;
    risk_score: number;
    observed_at: string | null;
  }>;
  vulnerabilities_list: Array<{
    id: number;
    title: string;
    severity: Severity;
    status: WorkflowStatus;
    cvss: number | null;
    neo_score: number;
    priority: Priority;
    protocol: string;
    port: number;
    service: string | null;
    cves: string[];
  }>;
  scan_history: Array<{
    scan_id: number;
    name: string;
    scanner: string;
    observed_at: string;
    credentialed: boolean;
    operating_system: string | null;
    vulnerabilities: number;
    critical: number;
    high: number;
    risk_score: number;
  }>;
}

interface AssetBusinessOwner {
  id: string;
  name: string;
  email: string;
}

interface AssetBusinessContext {
  environment: BusinessEnvironment | null;
  business_criticality: BusinessCriticality | null;
  owner: AssetBusinessOwner | null;
  responsible_team: string | null;
  business_service: string | null;
  business_unit: string | null;
  internet_exposed: boolean | null;
  maintenance_window: string | null;
  tags: string[];
  notes: string | null;
  updated_at: string | null;
  updated_by_name: string | null;
  can_edit: boolean;
}

interface ContextOwnerOption extends AssetBusinessOwner {
  role: "administrador" | "gestor" | "analista" | "visualizador";
}

const TABS: Array<{ id: AssetTab; label: string }> = [
  { id: "overview", label: "Visão geral" },
  { id: "business", label: "Contexto do negócio" },
  { id: "network", label: "Rede e serviços" },
  { id: "vulnerabilities", label: "Vulnerabilidades" },
  { id: "history", label: "Histórico" },
  { id: "evidence", label: "Evidências" },
];

export function AssetDetailWorkspace({ asset }: { asset: AssetDetail }) {
  const [activeTab, setActiveTab] = useState<AssetTab>("overview");
  const priority = priorityCopy(asset.priority, asset.vulnerabilities === 0);

  return (
    <div className="page-content">
      <Link className="detail-back" href="/assets">
        ← Voltar para o inventário
      </Link>

      <PageTitle
        eyebrow={asset.credentialed ? "Scan credenciado" : "Cobertura limitada"}
        title={asset.name}
        description={`${asset.address} · ${asset.operating_system ?? "Sistema operacional não identificado"}`}
        action={
          <div className={`neo-score-hero neo-score-hero--${asset.priority}`}>
            <span>RISCO DO ATIVO</span>
            <strong>{asset.risk_score}</strong>
            <small>{priority.label}</small>
          </div>
        }
      />

      <section className="detail-summary-grid" aria-label="Resumo do ativo">
        <SummaryCard
          helper="Achados ativos neste host"
          label="VULNERABILIDADES"
          value={asset.vulnerabilities.toString()}
        />
        <SummaryCard
          helper={`${asset.high} de severidade alta`}
          label="EXPOSIÇÃO CRÍTICA"
          value={asset.critical.toString()}
        />
        <SummaryCard
          helper={asset.credentialed ? "Coleta autenticada" : "Cobertura pode estar incompleta"}
          label="COBERTURA"
          value={asset.credentialed ? "Credenciada" : "Não credenciada"}
        />
        <SummaryCard
          helper={`${asset.inventory.scans_observed} scans no histórico`}
          label="VISTO POR ÚLTIMO"
          value={formatDate(asset.last_seen)}
        />
      </section>

      <nav className={styles.tabs} aria-label="Áreas do ativo" role="tablist">
        {TABS.map((tab) => (
          <button
            aria-controls={`asset-panel-${tab.id}`}
            aria-selected={activeTab === tab.id}
            className={activeTab === tab.id ? styles.activeTab : undefined}
            id={`asset-tab-${tab.id}`}
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            role="tab"
            type="button"
          >
            {tab.label}
            {tab.id === "vulnerabilities" && <small>{asset.vulnerabilities}</small>}
          </button>
        ))}
      </nav>

      <div
        aria-labelledby={`asset-tab-${activeTab}`}
        id={`asset-panel-${activeTab}`}
        role="tabpanel"
      >
        {activeTab === "overview" && <Overview asset={asset} priority={priority} />}
        {activeTab === "business" && (
          <BusinessContext assetId={asset.id} initialContext={asset.business_context} />
        )}
        {activeTab === "network" && <NetworkServices asset={asset} />}
        {activeTab === "vulnerabilities" && <Vulnerabilities asset={asset} />}
        {activeTab === "history" && <History asset={asset} />}
        {activeTab === "evidence" && <Evidence asset={asset} />}
      </div>
    </div>
  );
}

function Overview({
  asset,
  priority,
}: {
  asset: AssetDetail;
  priority: ReturnType<typeof priorityCopy>;
}) {
  return (
    <section className={styles.layout}>
      <div className={styles.mainColumn}>
        <ChangePanel changes={asset.changes} />

        <article className={`panel ${styles.panel}`}>
          <PanelHeading
            description="O que o scanner conseguiu identificar e com qual profundidade"
            title="Cobertura do último scan"
          />
          <div className={styles.coverageGrid}>
            <Metric
              label="AUTENTICAÇÃO"
              tone={asset.coverage.credentialed ? "good" : "warning"}
              value={asset.coverage.credentialed ? "Confirmada" : "Não confirmada"}
            />
            <Metric
              label="PROTOCOLO LOCAL"
              value={asset.coverage.local_checks_protocol?.toUpperCase() ?? "Não informado"}
            />
            <Metric
              label="DURAÇÃO"
              value={formatDuration(asset.coverage.duration_seconds)}
            />
            <Metric
              label="CONFIANÇA NO SO"
              value={formatConfidence(asset.facts.operating_system_confidence)}
            />
          </div>
          {!asset.coverage.credentialed && (
            <div className={styles.coverageWarning}>
              <Icon name="info" size={18} />
              <span>
                O scan não credenciado pode não enxergar pacotes, patches e configurações internas.
                Trate o inventário como cobertura parcial.
              </span>
            </div>
          )}
        </article>
      </div>

      <aside className={styles.sideColumn}>
        <article className={`panel ${styles.sidePanel}`}>
          <h2>Identidade técnica</h2>
          <dl className={styles.facts}>
            <Fact label="Endereço IP" value={asset.address} />
            <Fact label="FQDN" value={asset.fqdn} />
            <Fact label="NetBIOS" value={asset.facts.netbios} />
            <Fact label="Sistema operacional" value={asset.operating_system} />
            <Fact label="Tipo de sistema" value={asset.facts.system_type} />
            <Fact label="Endereço MAC" value={asset.facts.mac} />
            <Fact label="BIOS UUID" value={asset.facts.bios_uuid} />
          </dl>
        </article>

        <article className={`panel ${styles.riskExplanation}`}>
          <span>COMO LER O RISCO</span>
          <h2>{priority.label}</h2>
          <p>{priority.description}</p>
          <small>
            O risco do ativo representa o maior WVM Score entre suas vulnerabilidades abertas.
            Assim, um servidor importante não fica escondido por uma média baixa.
          </small>
        </article>
      </aside>
    </section>
  );
}


function BusinessContext({
  assetId,
  initialContext,
}: {
  assetId: number;
  initialContext: AssetBusinessContext;
}) {
  const router = useRouter();
  const [context, setContext] = useState(initialContext);
  const [owners, setOwners] = useState<ContextOwnerOption[]>([]);
  const [environment, setEnvironment] = useState(initialContext.environment ?? "");
  const [criticality, setCriticality] = useState(initialContext.business_criticality ?? "");
  const [ownerId, setOwnerId] = useState(initialContext.owner?.id ?? "");
  const [team, setTeam] = useState(initialContext.responsible_team ?? "");
  const [service, setService] = useState(initialContext.business_service ?? "");
  const [unit, setUnit] = useState(initialContext.business_unit ?? "");
  const [internetExposure, setInternetExposure] = useState(
    initialContext.internet_exposed === null
      ? "unknown"
      : initialContext.internet_exposed
        ? "yes"
        : "no",
  );
  const [maintenanceWindow, setMaintenanceWindow] = useState(
    initialContext.maintenance_window ?? "",
  );
  const [tags, setTags] = useState(initialContext.tags.join(", "));
  const [notes, setNotes] = useState(initialContext.notes ?? "");
  const [isLoadingOwners, setIsLoadingOwners] = useState(initialContext.can_edit);
  const [isSaving, setIsSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!initialContext.can_edit) return;
    const timeout = window.setTimeout(async () => {
      try {
        const response = await browserApi("/assets/context-options");
        if (response.status === 401) {
          router.replace("/login");
          return;
        }
        if (!response.ok) throw new Error(await readApiError(response));
        const payload = (await response.json()) as { owners: ContextOwnerOption[] };
        setOwners(payload.owners);
      } catch (loadError) {
        setError(
          loadError instanceof Error
            ? loadError.message
            : "Não foi possível carregar os responsáveis.",
        );
      } finally {
        setIsLoadingOwners(false);
      }
    }, 0);
    return () => window.clearTimeout(timeout);
  }, [initialContext.can_edit, router]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsSaving(true);
    setMessage(null);
    setError(null);
    try {
      const response = await browserApi(`/assets/${assetId}/business-context`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          environment: environment || null,
          business_criticality: criticality || null,
          owner_id: ownerId || null,
          responsible_team: team.trim() || null,
          business_service: service.trim() || null,
          business_unit: unit.trim() || null,
          internet_exposed:
            internetExposure === "unknown" ? null : internetExposure === "yes",
          maintenance_window: maintenanceWindow.trim() || null,
          tags: tags.split(",").map((tag) => tag.trim()).filter(Boolean),
          notes: notes.trim() || null,
        }),
      });
      if (response.status === 401) {
        router.replace("/login");
        return;
      }
      if (!response.ok) throw new Error(await readApiError(response));
      const updated = (await response.json()) as AssetBusinessContext;
      setContext(updated);
      setEnvironment(updated.environment ?? "");
      setCriticality(updated.business_criticality ?? "");
      setOwnerId(updated.owner?.id ?? "");
      setTeam(updated.responsible_team ?? "");
      setService(updated.business_service ?? "");
      setUnit(updated.business_unit ?? "");
      setInternetExposure(
        updated.internet_exposed === null ? "unknown" : updated.internet_exposed ? "yes" : "no",
      );
      setMaintenanceWindow(updated.maintenance_window ?? "");
      setTags(updated.tags.join(", "));
      setNotes(updated.notes ?? "");
      setMessage("Contexto de negócio atualizado e registrado na auditoria.");
      router.refresh();
    } catch (saveError) {
      setError(
        saveError instanceof Error
          ? saveError.message
          : "Não foi possível salvar o contexto de negócio.",
      );
    } finally {
      setIsSaving(false);
    }
  }

  return (
    <section className={styles.businessLayout}>
      <article className={`panel ${styles.businessHero}`}>
        <div>
          <span>CONTEXTO DE DECISÃO</span>
          <h2>O impacto real por trás do endereço IP</h2>
          <p>
            Estes dados ajudam a equipe a decidir a ordem de atuação, mas não alteram o WVM
            Score técnico calculado a partir da vulnerabilidade.
          </p>
        </div>
        <div className={styles.businessSnapshot}>
          <BusinessBadge
            label="AMBIENTE"
            value={environmentLabel(context.environment)}
          />
          <BusinessBadge
            label="CRITICIDADE"
            tone={context.business_criticality === "critica" ? "critical" : undefined}
            value={criticalityLabel(context.business_criticality)}
          />
          <BusinessBadge
            label="EXPOSIÇÃO EXTERNA"
            tone={context.internet_exposed ? "critical" : undefined}
            value={internetExposureLabel(context.internet_exposed)}
          />
          <BusinessBadge
            label="RESPONSÁVEL"
            tone={!context.owner ? "warning" : undefined}
            value={context.owner?.name ?? "Não definido"}
          />
        </div>
      </article>

      <form className={`panel ${styles.businessForm}`} onSubmit={handleSubmit}>
        <div className={styles.businessFormHeading}>
          <div>
            <h2>Cadastro operacional</h2>
            <p>Informações preenchidas pela equipe e independentes do scanner.</p>
          </div>
          {!context.can_edit && <span>Somente administradores e gestores podem editar</span>}
        </div>

        <fieldset disabled={!context.can_edit || isSaving}>
          <label className={styles.businessField}>
            <span>AMBIENTE</span>
            <select
              onChange={(event) => setEnvironment(event.target.value as BusinessEnvironment | "")}
              value={environment}
            >
              <option value="">Não definido</option>
              <option value="producao">Produção</option>
              <option value="homologacao">Homologação</option>
              <option value="desenvolvimento">Desenvolvimento</option>
              <option value="laboratorio">Laboratório</option>
              <option value="corporativo">Corporativo</option>
              <option value="outro">Outro</option>
            </select>
          </label>

          <label className={styles.businessField}>
            <span>CRITICIDADE PARA O NEGÓCIO</span>
            <select
              onChange={(event) => setCriticality(event.target.value as BusinessCriticality | "")}
              value={criticality}
            >
              <option value="">Não definida</option>
              <option value="critica">Crítica</option>
              <option value="alta">Alta</option>
              <option value="media">Média</option>
              <option value="baixa">Baixa</option>
            </select>
          </label>

          <label className={styles.businessField}>
            <span>RESPONSÁVEL TÉCNICO</span>
            <select
              disabled={!context.can_edit || isSaving || isLoadingOwners}
              onChange={(event) => setOwnerId(event.target.value)}
              value={ownerId}
            >
              <option value="">Sem responsável</option>
              {context.owner && !owners.some((owner) => owner.id === context.owner?.id) && (
                <option value={context.owner.id}>{context.owner.name} · acesso inativo</option>
              )}
              {owners.map((owner) => (
                <option key={owner.id} value={owner.id}>{owner.name} · {owner.email}</option>
              ))}
            </select>
          </label>

          <label className={styles.businessField}>
            <span>EQUIPE RESPONSÁVEL</span>
            <input
              maxLength={120}
              onChange={(event) => setTeam(event.target.value)}
              placeholder="Ex.: Infraestrutura Linux"
              value={team}
            />
          </label>

          <label className={styles.businessField}>
            <span>SISTEMA OU SERVIÇO DE NEGÓCIO</span>
            <input
              maxLength={160}
              onChange={(event) => setService(event.target.value)}
              placeholder="Ex.: Portal do cliente"
              value={service}
            />
          </label>

          <label className={styles.businessField}>
            <span>UNIDADE DE NEGÓCIO</span>
            <input
              maxLength={120}
              onChange={(event) => setUnit(event.target.value)}
              placeholder="Ex.: Operações"
              value={unit}
            />
          </label>

          <label className={styles.businessField}>
            <span>EXPOSTO À INTERNET</span>
            <select
              onChange={(event) => setInternetExposure(event.target.value)}
              value={internetExposure}
            >
              <option value="unknown">Não confirmado</option>
              <option value="yes">Sim</option>
              <option value="no">Não</option>
            </select>
          </label>

          <label className={styles.businessField}>
            <span>JANELA DE MANUTENÇÃO</span>
            <input
              maxLength={200}
              onChange={(event) => setMaintenanceWindow(event.target.value)}
              placeholder="Ex.: Domingos, 02h às 05h"
              value={maintenanceWindow}
            />
          </label>

          <label className={`${styles.businessField} ${styles.businessFieldWide}`}>
            <span>TAGS — SEPARE POR VÍRGULAS</span>
            <input
              onChange={(event) => setTags(event.target.value)}
              placeholder="Ex.: pci, legado, monitoramento-24x7"
              value={tags}
            />
          </label>

          <label className={`${styles.businessField} ${styles.businessFieldWide}`}>
            <span>OBSERVAÇÕES OPERACIONAIS</span>
            <textarea
              maxLength={2000}
              onChange={(event) => setNotes(event.target.value)}
              placeholder="Dependências, restrições ou informações relevantes para a remediação..."
              rows={5}
              value={notes}
            />
          </label>
        </fieldset>

        {error && <p className={styles.formError}>{error}</p>}
        {message && <p className={styles.formSuccess}>{message}</p>}
        <div className={styles.businessActions}>
          <small>
            {context.updated_at
              ? `Última atualização em ${formatDateTime(context.updated_at)}${
                  context.updated_by_name ? ` por ${context.updated_by_name}` : ""
                }.`
              : "O contexto ainda não foi preenchido."}
          </small>
          {context.can_edit && (
            <button className="button button--primary" disabled={isSaving} type="submit">
              {isSaving ? "Salvando..." : "Salvar contexto"}
            </button>
          )}
        </div>
      </form>
    </section>
  );
}

function BusinessBadge({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "critical" | "warning";
}) {
  return (
    <div className={`${styles.businessBadge} ${tone ? styles[`businessBadge_${tone}`] : ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}


function ChangePanel({ changes }: { changes: AssetDetail["changes"] }) {
  if (!changes.available) {
    return (
      <article className={`panel ${styles.changePanel}`}>
        <PanelHeading
          description="A próxima importação do mesmo escopo liberará a comparação"
          title="Mudanças desde o scan anterior"
        />
        <div className={styles.firstObservation}>
          <Icon name="scan" size={24} />
          <div>
            <strong>Primeira observação deste ativo</strong>
            <span>Ainda não há um scan anterior equivalente para comparar.</span>
          </div>
        </div>
      </article>
    );
  }

  const hasIdentityChange = changes.operating_system_changed || changes.credentialed_changed;
  return (
    <article className={`panel ${styles.changePanel}`}>
      <PanelHeading
        description={`Comparado com ${changes.previous_scan_name ?? "o scan anterior"}${
          changes.previous_scan_at ? ` de ${formatDate(changes.previous_scan_at)}` : ""
        }`}
        title="Mudanças desde o scan anterior"
      />
      <div className={styles.changeGrid}>
        <ChangeMetric label="NOVAS" tone="bad" value={changes.new_findings} />
        <ChangeMetric label="CORRIGIDAS" tone="good" value={changes.corrected_findings} />
        <ChangeMetric label="PERSISTENTES" value={changes.persistent_findings} />
        <ChangeMetric label="REABERTAS" tone="warning" value={changes.reopened_findings} />
        <ChangeMetric
          label="DELTA DE RISCO"
          tone={changes.risk_delta > 0 ? "bad" : changes.risk_delta < 0 ? "good" : undefined}
          value={formatSigned(changes.risk_delta)}
        />
      </div>
      {(changes.ports_added.length > 0 || changes.ports_removed.length > 0 || hasIdentityChange) && (
        <div className={styles.changeNotes}>
          {changes.ports_added.length > 0 && (
            <span>Novas portas: {changes.ports_added.map(formatServiceReference).join(", ")}</span>
          )}
          {changes.ports_removed.length > 0 && (
            <span>Portas removidas: {changes.ports_removed.map(formatServiceReference).join(", ")}</span>
          )}
          {changes.operating_system_changed && <span>O sistema operacional identificado mudou.</span>}
          {changes.credentialed_changed && <span>O status de autenticação do scan mudou.</span>}
        </div>
      )}
    </article>
  );
}

function NetworkServices({ asset }: { asset: AssetDetail }) {
  return (
    <section className={styles.singleColumn}>
      <article className={`panel ${styles.panel}`}>
        <PanelHeading
          description="Portas vistas no último scan, inclusive quando não possuem vulnerabilidades"
          title="Inventário de rede e serviços"
        />
        <div className={styles.networkSummary}>
          <Metric label="SERVIÇOS OBSERVADOS" value={asset.inventory.observed_services.toString()} />
          <Metric
            label="COM ACHADOS"
            tone={asset.inventory.services_with_findings > 0 ? "warning" : "good"}
            value={asset.inventory.services_with_findings.toString()}
          />
          <Metric
            label="SEM ACHADOS"
            value={Math.max(
              asset.inventory.observed_services - asset.inventory.services_with_findings,
              0,
            ).toString()}
          />
        </div>
        {asset.services.length > 0 ? (
          <div className={styles.serviceTable}>
            <div className={styles.serviceHeader}>
              <span>PORTA</span>
              <span>SERVIÇO</span>
              <span>OBSERVADO EM</span>
              <span>ACHADOS</span>
              <span>RISCO</span>
            </div>
            {asset.services.map((service) => (
              <div className={styles.serviceTableRow} key={`${service.protocol}-${service.port}`}>
                <span className={styles.portIdentity}>
                  <strong>{service.port}</strong>
                  <small>{service.protocol.toUpperCase()}</small>
                </span>
                <span>{service.service ?? "Serviço não identificado"}</span>
                <span>{service.observed_at ? formatDateTime(service.observed_at) : "Via achado ativo"}</span>
                <span className={service.vulnerabilities > 0 ? styles.exposedService : styles.cleanService}>
                  {service.vulnerabilities > 0 ? service.vulnerabilities : "Sem achados"}
                </span>
                <span className={`${styles.findingScore} ${styles[`score_${priorityForScore(service.risk_score)}`]}`}>
                  {service.risk_score}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            description="Nenhuma porta foi identificada no último scan deste ativo."
            icon={<Icon name="assets" size={26} />}
            title="Sem serviços observados"
          />
        )}
      </article>
    </section>
  );
}

function Vulnerabilities({ asset }: { asset: AssetDetail }) {
  return (
    <section className={styles.singleColumn}>
      <article className={`panel ${styles.panel}`}>
        <PanelHeading
          description="Achados ativos ordenados pela urgência técnica"
          title="Vulnerabilidades do ativo"
        />
        {asset.vulnerabilities_list.length > 0 ? (
          <div className={styles.vulnerabilityList}>
            <div className={styles.vulnerabilityHeader}>
              <span>ACHADO</span>
              <span>EXPOSIÇÃO</span>
              <span>STATUS</span>
              <span>WVM SCORE</span>
            </div>
            {asset.vulnerabilities_list.map((finding) => (
              <Link
                className={styles.vulnerabilityRow}
                href={`/vulnerabilities/${finding.id}`}
                key={finding.id}
              >
                <span className={styles.findingIdentity}>
                  <strong>{finding.title}</strong>
                  <small>{finding.cves.slice(0, 2).join(" · ") || "Sem CVE associado"}</small>
                </span>
                <span className={styles.findingExposure}>
                  <SeverityBadge severity={finding.severity} />
                  <small>
                    {finding.port > 0
                      ? `${finding.protocol.toUpperCase()}/${finding.port}`
                      : "Local"}
                  </small>
                </span>
                <span className={styles.workflowStatus}>{statusLabel(finding.status)}</span>
                <span className={`${styles.findingScore} ${styles[`score_${finding.priority}`]}`}>
                  {finding.neo_score}
                </span>
              </Link>
            ))}
          </div>
        ) : (
          <EmptyState
            description="Nenhum achado ativo foi relacionado a este host no estado atual."
            icon={<Icon name="shield" size={26} />}
            title="Ativo sem vulnerabilidades abertas"
          />
        )}
      </article>
    </section>
  );
}

function History({ asset }: { asset: AssetDetail }) {
  return (
    <section className={styles.singleColumn}>
      <article className={`panel ${styles.panel}`}>
        <PanelHeading
          description="Como a exposição, a cobertura e o sistema identificado mudaram"
          title="Histórico de scans"
        />
        {asset.scan_history.length > 0 ? (
          <div className={styles.historyList}>
            {asset.scan_history.map((scan, index) => (
              <div className={styles.historyRow} key={scan.scan_id}>
                <span className={styles.timelineMarker} aria-hidden="true">
                  <i />
                  {index < asset.scan_history.length - 1 && <b />}
                </span>
                <span className={styles.historyIdentity}>
                  <strong>{scan.name}</strong>
                  <small>{formatDateTime(scan.observed_at)} · {scan.scanner.toUpperCase()}</small>
                </span>
                <span className={styles.historyCoverage}>
                  {scan.credentialed ? "Credenciado" : "Não credenciado"}
                  <small>{scan.operating_system ?? "SO não identificado"}</small>
                </span>
                <span className={styles.historyCounts}>
                  <strong>{scan.vulnerabilities}</strong>
                  <small>{scan.critical} críticas · {scan.high} altas</small>
                </span>
                <span className={styles.historyRisk}>
                  <i style={{ width: `${Math.max(scan.risk_score, 2)}%` }} />
                  <strong>{scan.risk_score}</strong>
                </span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            description="O histórico aparecerá conforme novos scans forem importados."
            icon={<Icon name="scan" size={26} />}
            title="Sem histórico disponível"
          />
        )}
      </article>
    </section>
  );
}

function Evidence({ asset }: { asset: AssetDetail }) {
  return (
    <section className={styles.evidenceLayout}>
      <article className={`panel ${styles.sidePanel}`}>
        <h2>Proveniência do inventário</h2>
        <dl className={styles.facts}>
          <Fact label="Política" value={asset.coverage.policy_used} />
          <Fact label="Início do scan" value={formatNullableDateTime(asset.coverage.scan_started_at)} />
          <Fact label="Fim do scan" value={formatNullableDateTime(asset.coverage.scan_ended_at)} />
          <Fact
            label="Último resultado autenticado"
            value={formatNullableDateTime(asset.coverage.last_authenticated_results_at)}
          />
          <Fact
            label="Último não autenticado"
            value={formatNullableDateTime(asset.coverage.last_unauthenticated_results_at)}
          />
          <Fact label="Primeira observação" value={formatDateTime(asset.inventory.first_seen)} />
          <Fact label="Última observação" value={formatDateTime(asset.inventory.last_seen)} />
        </dl>
      </article>

      <article className={`panel ${styles.sidePanel}`}>
        <h2>Fingerprint do sistema</h2>
        <dl className={styles.facts}>
          <Fact label="Sistema operacional" value={asset.operating_system} />
          <Fact label="Método de identificação" value={asset.facts.operating_system_method} />
          <Fact label="Confiança" value={formatConfidence(asset.facts.operating_system_confidence)} />
          <Fact label="BIOS UUID" value={asset.facts.bios_uuid} />
          <Fact
            label="CVEs no resumo de patches"
            value={asset.inventory.patch_summary_total_cves?.toString() ?? null}
          />
        </dl>
        <div className={styles.cpeBlock}>
          <span>CPES IDENTIFICADOS</span>
          {asset.facts.cpes.length > 0 ? (
            <div>
              {asset.facts.cpes.map((cpe) => <code key={cpe}>{cpe}</code>)}
            </div>
          ) : (
            <p>Nenhum CPE informado pelo scanner.</p>
          )}
        </div>
      </article>

      <div className={styles.evidenceNotice}>
        <Icon name="shield" size={20} />
        <span>
          O WVM guarda apenas uma seleção estruturada de metadados úteis. Saídas brutas e campos
          potencialmente sensíveis do scanner não são expostos nesta tela.
        </span>
      </div>
    </section>
  );
}

function SummaryCard({ label, value, helper }: { label: string; value: string; helper: string }) {
  return (
    <article className="panel detail-summary-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{helper}</small>
    </article>
  );
}

function PanelHeading({ title, description }: { title: string; description: string }) {
  return (
    <div className="panel__heading">
      <div>
        <h2>{title}</h2>
        <p>{description}</p>
      </div>
    </div>
  );
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "good" | "warning";
}) {
  return (
    <div className={`${styles.metric} ${tone ? styles[`metric_${tone}`] : ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ChangeMetric({
  label,
  value,
  tone,
}: {
  label: string;
  value: string | number;
  tone?: "good" | "warning" | "bad";
}) {
  return (
    <div className={`${styles.changeMetric} ${tone ? styles[`changeMetric_${tone}`] : ""}`}>
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string | null }) {
  return <div><dt>{label}</dt><dd>{value || "Não informado"}</dd></div>;
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

function statusLabel(status: WorkflowStatus) {
  return {
    open: "Aberta",
    triage: "Em triagem",
    in_progress: "Em correção",
    validation: "Em validação",
    accepted_risk: "Risco aceito",
    resolved: "Resolvida",
    reopened: "Reaberta",
  }[status];
}

function priorityCopy(priority: Priority, clean: boolean) {
  if (clean) {
    return {
      label: "Sem achados",
      description: "O estado atual não possui vulnerabilidades abertas para este ativo.",
    };
  }
  return {
    act_now: {
      label: "Agir agora",
      description: "O ativo contém ao menos um achado com sinais de urgência imediata.",
    },
    prioritize: {
      label: "Priorizar",
      description: "Inclua este ativo no próximo ciclo de remediação e confirme o responsável.",
    },
    plan: {
      label: "Planejar",
      description: "Há exposição ativa que deve entrar no planejamento de correção.",
    },
    monitor: {
      label: "Monitorar",
      description: "Mantenha o ativo visível e acompanhe mudanças nos próximos scans.",
    },
  }[priority];
}

function priorityForScore(score: number): Priority {
  if (score >= 80) return "act_now";
  if (score >= 60) return "prioritize";
  if (score >= 35) return "plan";
  return "monitor";
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeZone: "America/Sao_Paulo",
  }).format(new Date(value));
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo",
  }).format(new Date(value));
}

function formatNullableDateTime(value: string | null) {
  return value ? formatDateTime(value) : null;
}

function formatDuration(seconds: number | null) {
  if (seconds === null) return "Não informada";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return remainingSeconds > 0 ? `${minutes}min ${remainingSeconds}s` : `${minutes}min`;
}

function formatConfidence(value: number | null) {
  if (value === null || value < 0) return "Não informada";
  return `${value}%`;
}

function formatSigned(value: number) {
  return value > 0 ? `+${value}` : value.toString();
}

function formatServiceReference(service: ServiceReference) {
  const name = service.service ? ` ${service.service}` : "";
  return `${service.protocol.toUpperCase()}/${service.port}${name}`;
}

function environmentLabel(value: BusinessEnvironment | null) {
  if (value === null) return "Não definido";
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
  if (value === null) return "Não definida";
  return {
    critica: "Crítica",
    alta: "Alta",
    media: "Média",
    baixa: "Baixa",
  }[value];
}

function internetExposureLabel(value: boolean | null) {
  if (value === null) return "Não confirmada";
  return value ? "Exposto" : "Não exposto";
}
