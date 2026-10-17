"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { browserApi, readApiError } from "@/lib/api";

export function LoginForm() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setIsLoading(true);
    const formData = new FormData(event.currentTarget);
    try {
      const response = await browserApi("/auth/login", {
        method: "POST",
        signal: AbortSignal.timeout(15000),
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: formData.get("email"),
          password: formData.get("password"),
        }),
      });
      if (!response.ok) {
        setError(response.status >= 500
          ? "A API respondeu, mas não conseguiu concluir o login. Peça ao responsável para verificar o banco e executar npm run doctor na pasta do projeto."
          : await readApiError(response));
        return;
      }
      router.replace("/dashboard");
      router.refresh();
    } catch (loginError) {
      const timedOut = loginError instanceof Error && loginError.name === "TimeoutError";
      setError(timedOut
        ? "O login demorou mais que o esperado. Tente novamente; se persistir, execute npm run doctor na pasta do projeto."
        : "Não foi possível conectar à API. Confira se os serviços estão em execução e se o endereço e a permissão de acesso (CORS) estão corretos. Para diagnosticar, execute npm run doctor na pasta do projeto.");
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <form className="login-form" onSubmit={handleLogin}>
      <label htmlFor="email">E-mail corporativo</label>
      <input
        autoComplete="email"
        id="email"
        name="email"
        placeholder="voce@empresa.com.br"
        required
        type="email"
      />

      <div className="login-form__password-label">
        <label htmlFor="password">Senha</label>
        <span>Ambiente protegido</span>
      </div>
      <input
        autoComplete="current-password"
        id="password"
        minLength={8}
        name="password"
        placeholder="••••••••••••"
        required
        type="password"
      />

      <button className="button button--primary button--full" disabled={isLoading} type="submit">
        {isLoading ? "Entrando..." : "Entrar na plataforma"}
      </button>

      {error && <p className="form-error" role="alert">{error}</p>}
    </form>
  );
}
