"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { PageTitle } from "@/components/page-title";
import { browserApi, readApiError } from "@/lib/api";
import styles from "./jira-admin-workspace.module.css";

interface Configuration {
  configured: boolean; encryption_ready: boolean; outbound_enabled: boolean;
  version: number; site_url: string; email: string; project_key: string;
  issue_type: string; cloud_id: string; include_asset_details: boolean;
  has_token: boolean; active: boolean; test_ok: boolean; tested_at: string | null; error: string | null;
}

export function JiraAdminWorkspace() {
  const router = useRouter();
  const [saved, setSaved] = useState<Configuration | null>(null);
  const [form, setForm] = useState<Configuration | null>(null);
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [reload, setReload] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    async function load() {
      try {
        const response = await browserApi("/admin/jira", { cache: "no-store", signal: controller.signal });
        if (response.status === 401 || response.status === 403) {
          router.replace(response.status === 401 ? "/login" : "/dashboard"); return;
        }
        if (!response.ok) throw new Error(await readApiError(response));
        const data = await response.json() as Configuration;
        setSaved(data); setForm(data); setError(null);
      } catch { if (!controller.signal.aborted) setError("Não foi possível carregar a integração."); }
      finally { clearTimeout(timeout); }
    }
    void load();
    return () => { controller.abort(); clearTimeout(timeout); };
  }, [router, reload]);

  const dirty = JSON.stringify(form) !== JSON.stringify(saved) || token.length > 0;
  async function action(kind: "save" | "test" | "activate" | "disable") {
    if (!form || busy) return;
    setBusy(true); setError(null); setNotice("");
    const body = kind === "save" ? {
      version: form.version, site_url: form.site_url.trim(), email: form.email.trim(),
      project_key: form.project_key.trim(), issue_type: form.issue_type.trim(),
      cloud_id: form.cloud_id.trim() || null, include_asset_details: form.include_asset_details,
      api_token: token || null,
    } : { version: form.version };
    try {
      const response = await browserApi(`/admin/jira${kind === "save" ? "" : `/${kind}`}`, {
        method: kind === "save" ? "PATCH" : "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body), signal: AbortSignal.timeout(75000),
      });
      if (response.status === 401 || response.status === 403) {
        router.replace(response.status === 401 ? "/login" : "/dashboard"); return;
      }
      if (!response.ok) throw new Error(await readApiError(response));
      const data = await response.json() as Configuration;
      setSaved(data); setForm(data);
      setNotice(kind === "save" ? "Configuração salva. Teste a conexão antes de ativar." :
        kind === "test" ? data.test_ok ? "Conexão e permissões verificadas. Nenhum ticket foi criado." : "O teste falhou. Confira a orientação abaixo." :
        kind === "activate" ? "Integração ativada para esta empresa." : "Integração desativada. Os vínculos existentes foram preservados.");
    } catch (cause) {
      setError(cause instanceof Error && cause.name !== "TimeoutError" ? cause.message : "A solicitação não foi confirmada. Recarregue o cadastro antes de tentar novamente.");
    } finally { setToken(""); setBusy(false); }
  }

  return <div className={styles.workspace}>
    <PageTitle eyebrow="ADMINISTRAÇÃO" title="Integração Jira" description="O Jira da sua empresa, conectado ao tratamento das vulnerabilidades." />
    <section className={`panel ${styles.panel}`}>
      <div className={styles.heading}><h2>Conexão da empresa</h2><strong>{saved?.active ? "Ativa" : "Desativada"}</strong></div>
      <p>Somente administradores configuram esta conexão. Cada empresa usa suas próprias credenciais, projeto e tickets. Nesta versão, a integração atende ao Jira Cloud.</p>
      {error && <p role="alert" className={styles.warning}>{error}</p>}
      {notice && <p role="status" className={styles.notice}>{notice}</p>}
      {!form ? <button className="button button--secondary" onClick={() => setReload(n => n + 1)}>Carregar cadastro</button> : <>
        {!form.encryption_ready && <p className={styles.warning}>A chave de proteção do servidor ainda não foi configurada. O cadastro de credenciais está bloqueado.</p>}
        {!form.outbound_enabled && <p className={styles.warning}>As conexões externas com o Jira estão desativadas neste servidor.</p>}
        <form onSubmit={event => { event.preventDefault(); void action("save"); }}>
          <fieldset disabled={busy || !form.encryption_ready} className={styles.fields}>
            <label>Endereço Jira Cloud<input required type="url" maxLength={255} placeholder="https://empresa.atlassian.net" value={form.site_url} onChange={e => setForm({ ...form, site_url: e.target.value })} /></label>
            <label>E-mail da conta de integração<input required type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} /></label>
            <label>Token da API {saved?.has_token ? "· já configurado" : ""}<input type="password" required={!saved?.has_token} autoComplete="new-password" maxLength={4096} value={token} onChange={e => setToken(e.target.value)} placeholder={saved?.has_token ? "Deixe vazio para manter o token" : "Cole o token aqui, nunca no chat"} /><small>Gravado criptografado. O token salvo nunca é devolvido à tela.</small></label>
            <label>Cloud ID (para token com escopos)<input value={form.cloud_id} onChange={e => setForm({ ...form, cloud_id: e.target.value })} placeholder="UUID do site, se necessário" /><small>Tokens com escopos usam o endereço de API da Atlassian e precisam deste identificador.</small></label>
            <label>Chave do projeto<input required pattern="[A-Z][A-Z0-9_]{1,29}" maxLength={30} placeholder="SEC" value={form.project_key} onChange={e => setForm({ ...form, project_key: e.target.value })} /></label>
            <label>Tipo de item (nome exato ou ID)<input required maxLength={80} placeholder="Task, Tarefa ou ID" value={form.issue_type} onChange={e => setForm({ ...form, issue_type: e.target.value })} /></label>
            <label className={styles.checkbox}><input type="checkbox" checked={form.include_asset_details} onChange={e => setForm({ ...form, include_asset_details: e.target.checked })} />Permitir IP e nome do ativo no ticket</label>
          </fieldset>
          <p className={styles.help}>Salvar desativa a conexão até um novo teste e ativação. Textos livres devem ser revisados na prévia do chamado. Responsável, prazo e etapa são enviados como contexto, sem alterar usuários ou fluxos do Jira.</p>
          <div className={styles.actions}>
            <button type="submit" className="button button--primary" disabled={busy || !form.encryption_ready || !dirty}>Salvar configuração</button>
            <button type="button" className="button button--secondary" disabled={busy || dirty || !saved?.configured || !form.outbound_enabled} onClick={() => void action("test")}>Testar conexão</button>
            <button type="button" className="button button--secondary" disabled={busy || dirty || !saved?.test_ok || saved.active || !form.outbound_enabled} onClick={() => void action("activate")}>Ativar integração</button>
            {saved?.active && <button type="button" className="button button--secondary" disabled={busy || dirty} onClick={() => void action("disable")}>Desativar</button>}
            <button type="button" className="button button--secondary" disabled={busy} onClick={() => { setToken(""); setReload(n => n + 1); }}>Recarregar cadastro</button>
          </div>
        </form>
        {busy && <p role="status">Processando… sem criar tickets neste cadastro.</p>}
        {saved?.error && <p role="alert" className={styles.warning}>{saved.error}</p>}
        <p className={styles.help}>Fluxo: salvar → testar → ativar. Criar tickets é uma ação separada, com confirmação na vulnerabilidade. A conta precisa consultar o projeto e criar itens com descrição e etiquetas, sem campos obrigatórios adicionais não suportados.</p>
      </>}
    </section>
  </div>;
}
