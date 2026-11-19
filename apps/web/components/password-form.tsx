"use client";

import Link from "next/link";
import { useEffect, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Brand } from "@/components/brand";
import { browserApi, readApiError } from "@/lib/api";
import styles from "./password-form.module.css";

export function PasswordForm({ mode }: { mode: "forgot" | "reset" | "change" }) {
  const router = useRouter();
  const [token, setToken] = useState("");
  const [ready, setReady] = useState(mode === "forgot");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  useEffect(() => {
    if (mode === "reset") {
      const consume = () => {
      const value = new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
      window.history.replaceState(null, "", window.location.pathname);
      setToken(value); setReady(value.length === 43);
      setError(value.length === 43 ? "" : "Link inválido ou incompleto. Solicite outro link de recuperação.");
      };
      const timer = window.setTimeout(consume, 0);
      window.addEventListener("hashchange", consume);
      return () => { window.clearTimeout(timer); window.removeEventListener("hashchange", consume); };
    }
    if (mode === "change") {
      const controller = new AbortController();
      void browserApi("/auth/me", { signal: controller.signal }).then(response => {
        if (response.status === 401) router.replace("/login");
        else if (response.ok) setReady(true);
        else setError("Não foi possível verificar sua sessão.");
      }).catch(() => { if (!controller.signal.aborted) setError("Não foi possível conectar à API. Recarregue a página."); });
      return () => controller.abort();
    }
  }, [mode, router]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || busy) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const password = String(fields.get("new_password") ?? "");
    if (mode !== "forgot" && password !== fields.get("confirmation")) {
      setError("As duas senhas precisam ser iguais."); return;
    }
    setBusy(true); setError("");
    const body = mode === "forgot" ? { email: fields.get("email") } : mode === "reset"
      ? { token, new_password: password } : { current_password: fields.get("current_password"), new_password: password };
    try {
      const response = await browserApi(`/auth/${mode === "forgot" ? "forgot-password" : mode === "reset" ? "reset-password" : "change-password"}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000),
      });
      if (response.status === 401) { router.replace("/login"); return; }
      if (!response.ok) throw new Error(await readApiError(response));
      setMessage((await response.json()).message); form.reset(); setToken("");
    } catch (cause) {
      setError(cause instanceof Error && cause.name !== "TimeoutError" ? cause.message : "A solicitação não foi confirmada. Tente entrar com a nova senha antes de repetir a alteração.");
    } finally { setBusy(false); }
  }
  const title = mode === "forgot" ? "Recuperar acesso" : mode === "reset" ? "Redefinir senha" : "Alterar minha senha";
  return <section className={styles.page}><div className={`login-card ${styles.card}`}>
    <Brand /><h1>{title}</h1>
    <p>{mode === "forgot" ? "Informe o e-mail cadastrado para receber um link de recuperação." : mode === "change" ? "No primeiro acesso, substitua a senha inicial por uma senha só sua. A alteração encerra as sessões anteriores." : "Escolha uma nova senha. O link só pode ser usado uma vez e expira em 20 minutos."}</p>
    {message ? <p role="status">{message}</p> : <form className="login-form" onSubmit={submit}>
      {mode === "forgot" ? <><label htmlFor="recovery-email">E-mail cadastrado</label><input id="recovery-email" type="email" name="email" autoComplete="email" required /></> : <>
        {mode === "change" && <><label htmlFor="current-password">Senha atual ou inicial</label><input id="current-password" name="current_password" type="password" autoComplete="current-password" maxLength={200} required /></>}
        <label htmlFor="new-password">Nova senha</label><input id="new-password" name="new_password" type="password" autoComplete="new-password" minLength={12} maxLength={200} required />
        <label htmlFor="confirmation">Confirmar nova senha</label><input id="confirmation" name="confirmation" type="password" autoComplete="new-password" minLength={12} maxLength={200} required />
        <small>Use uma senha exclusiva com pelo menos 12 caracteres. Você pode usar um gerenciador de senhas.</small>
      </>}
      <button className="button button--primary" disabled={busy || !ready}>{busy ? "Processando..." : mode === "forgot" ? "Enviar link de recuperação" : "Salvar nova senha"}</button>
    </form>}
    {error && <p className="form-error" role="alert">{error}</p>}
    <div className={styles.links}><Link href="/login">Voltar para o login</Link>{mode !== "forgot" && <Link href="/forgot-password">Solicitar recuperação</Link>}</div>
  </div></section>;
}
