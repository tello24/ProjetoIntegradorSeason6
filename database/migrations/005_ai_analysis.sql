BEGIN;

CREATE TABLE IF NOT EXISTS app.vulnerabilidade_analise_ia (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cliente_id          bigint NOT NULL REFERENCES vm.cliente(id) ON DELETE CASCADE,
    tratamento_id       uuid NOT NULL
                            REFERENCES app.vulnerabilidade_tratamento(id) ON DELETE CASCADE,
    geracao             integer NOT NULL,
    ativa               boolean NOT NULL DEFAULT true,
    provedor            text NOT NULL,
    modelo              text NOT NULL,
    versao_prompt       text NOT NULL,
    assinatura_entrada  char(64) NOT NULL,
    conteudo            jsonb NOT NULL,
    tokens_entrada      integer NOT NULL DEFAULT 0,
    tokens_saida        integer NOT NULL DEFAULT 0,
    tokens_total        integer NOT NULL DEFAULT 0,
    custo_estimado_usd  numeric(14, 8) NOT NULL DEFAULT 0,
    motivo_geracao      text NOT NULL DEFAULT 'initial',
    criado_por          uuid REFERENCES app.usuario(id) ON DELETE SET NULL,
    criado_em           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT vulnerabilidade_analise_ia_provedor_valido CHECK (
        provedor IN ('anthropic', 'openai')
    ),
    CONSTRAINT vulnerabilidade_analise_ia_geracao_valida CHECK (geracao > 0),
    CONSTRAINT vulnerabilidade_analise_ia_tokens_validos CHECK (
        tokens_entrada >= 0 AND tokens_saida >= 0 AND tokens_total >= 0
    ),
    CONSTRAINT vulnerabilidade_analise_ia_custo_valido CHECK (custo_estimado_usd >= 0),
    CONSTRAINT vulnerabilidade_analise_ia_motivo_valido CHECK (
        motivo_geracao IN ('initial', 'manual_regeneration')
    ),
    CONSTRAINT vulnerabilidade_analise_ia_geracao_unica UNIQUE (tratamento_id, geracao)
);

CREATE UNIQUE INDEX IF NOT EXISTS vulnerabilidade_analise_ia_atual_idx
    ON app.vulnerabilidade_analise_ia (tratamento_id)
    WHERE ativa = true;

CREATE INDEX IF NOT EXISTS vulnerabilidade_analise_ia_cliente_data_idx
    ON app.vulnerabilidade_analise_ia (cliente_id, criado_em DESC);

CREATE INDEX IF NOT EXISTS vulnerabilidade_analise_ia_historico_idx
    ON app.vulnerabilidade_analise_ia (tratamento_id, geracao DESC);

COMMIT;
