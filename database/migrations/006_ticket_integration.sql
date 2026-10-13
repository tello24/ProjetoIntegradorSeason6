BEGIN;

CREATE TABLE IF NOT EXISTS app.vulnerabilidade_ticket (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cliente_id          bigint NOT NULL REFERENCES vm.cliente(id) ON DELETE CASCADE,
    tratamento_id       uuid NOT NULL
                            REFERENCES app.vulnerabilidade_tratamento(id) ON DELETE CASCADE,
    provedor            text NOT NULL,
    status              text NOT NULL DEFAULT 'creating',
    chave_externa       text,
    url_externa         text,
    resumo              text NOT NULL,
    ultimo_erro         text,
    criado_por          uuid REFERENCES app.usuario(id) ON DELETE SET NULL,
    criado_em           timestamptz NOT NULL DEFAULT now(),
    atualizado_em       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT vulnerabilidade_ticket_status_valido CHECK (
        status IN ('creating', 'created', 'failed')
    ),
    CONSTRAINT vulnerabilidade_ticket_unico UNIQUE (tratamento_id, provedor)
);

CREATE INDEX IF NOT EXISTS vulnerabilidade_ticket_cliente_data_idx
    ON app.vulnerabilidade_ticket (cliente_id, criado_em DESC);

CREATE UNIQUE INDEX IF NOT EXISTS vulnerabilidade_ticket_chave_externa_idx
    ON app.vulnerabilidade_ticket (provedor, chave_externa)
    WHERE chave_externa IS NOT NULL;

COMMIT;
