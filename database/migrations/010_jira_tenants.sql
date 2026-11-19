BEGIN;

CREATE TABLE IF NOT EXISTS app.jira_integracao (
    cliente_id bigint PRIMARY KEY REFERENCES vm.cliente(id) ON DELETE CASCADE,
    site_url text NOT NULL,
    email text NOT NULL,
    token_cifrado text NOT NULL,
    projeto text NOT NULL,
    tipo_item text NOT NULL,
    cloud_id uuid,
    incluir_ativos boolean NOT NULL DEFAULT false,
    ativa boolean NOT NULL DEFAULT false,
    versao integer NOT NULL DEFAULT 1,
    teste_ok boolean NOT NULL DEFAULT false,
    testado_em timestamptz,
    ultimo_erro text,
    atualizado_por uuid REFERENCES app.usuario(id) ON DELETE SET NULL,
    atualizado_em timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE app.vulnerabilidade_ticket
    ADD COLUMN IF NOT EXISTS site_url text,
    ADD COLUMN IF NOT EXISTS projeto text,
    ADD COLUMN IF NOT EXISTS codigo_erro text;

ALTER TABLE app.vulnerabilidade_ticket
    DROP CONSTRAINT IF EXISTS vulnerabilidade_ticket_status_valido;
ALTER TABLE app.vulnerabilidade_ticket ADD CONSTRAINT vulnerabilidade_ticket_status_valido
    CHECK (status IN ('creating', 'created', 'failed', 'uncertain'));

-- Historical errors did not distinguish rejection from an ambiguous remote outcome.
UPDATE app.vulnerabilidade_ticket SET status = 'uncertain', codigo_erro = 'legacy_uncertain'
WHERE status = 'failed' AND site_url IS NULL;

DROP INDEX IF EXISTS app.vulnerabilidade_ticket_chave_externa_idx;
CREATE UNIQUE INDEX IF NOT EXISTS vulnerabilidade_ticket_cliente_chave_idx
    ON app.vulnerabilidade_ticket (cliente_id, provedor, site_url, chave_externa)
    WHERE chave_externa IS NOT NULL;

COMMIT;
