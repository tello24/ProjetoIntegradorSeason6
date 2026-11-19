BEGIN;
ALTER TABLE app.usuario
    ADD COLUMN IF NOT EXISTS trocar_senha boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS versao_sessao integer NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS app.recuperacao_senha (
    token_hash text PRIMARY KEY,
    usuario_id uuid NOT NULL REFERENCES app.usuario(id) ON DELETE CASCADE,
    expira_em timestamptz NOT NULL,
    criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS recuperacao_usuario_idx ON app.recuperacao_senha(usuario_id);
CREATE TABLE IF NOT EXISTS app.limite_autenticacao (
    chave text PRIMARY KEY,
    inicio timestamptz NOT NULL DEFAULT now(),
    tentativas integer NOT NULL DEFAULT 1
);
COMMIT;
