import type { Metadata } from "next";

import { Brand } from "@/components/brand";
import { Icon } from "@/components/icons";
import { LoginForm } from "@/components/login-form";

export const metadata: Metadata = {
  title: "Entrar",
};

export default function LoginPage() {
  return (
    <div className="login-page">
      <section className="login-page__story">
        <div className="login-page__grid" />
        <div className="login-page__glow" />
        <Brand />

        <div className="login-page__message">
          <p className="eyebrow">VISIBILIDADE QUE GERA AÇÃO</p>
          <h1>
            Vulnerabilidades sob controle. <span>Decisões com contexto.</span>
          </h1>
          <p>
            Centralize seus scans, entenda o risco real do ambiente e transforme achados
            técnicos em um plano claro de correção.
          </p>
        </div>

        <div className="login-page__trust">
          <Icon name="shield" size={18} />
          <span>Dados protegidos e isolados por organização</span>
        </div>
      </section>

      <section className="login-page__panel">
        <div className="login-card">
          <div className="login-card__mobile-brand">
            <Brand />
          </div>
          <p className="eyebrow">BEM-VINDO DE VOLTA</p>
          <h2>Acesse sua central</h2>
          <p className="login-card__description">
            Entre com sua conta para visualizar o panorama de segurança da sua organização.
          </p>
          <LoginForm />
        </div>
        <p className="login-page__legal">© 2026 NeoGuardian · WVM. Uso interno autorizado.</p>
      </section>
    </div>
  );
}
