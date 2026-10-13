BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'host_id_cliente_unique'
          AND conrelid = 'vm.host'::regclass
    ) THEN
        ALTER TABLE vm.host
            ADD CONSTRAINT host_id_cliente_unique UNIQUE (id, cliente_id);
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS app.ativo_contexto (
    cliente_id          bigint NOT NULL,
    host_id             bigint NOT NULL,
    ambiente            text,
    criticidade_negocio text,
    responsavel_id      uuid REFERENCES app.usuario(id) ON DELETE SET NULL,
    equipe_responsavel  text,
    servico_negocio     text,
    unidade_negocio     text,
    exposto_internet    boolean,
    janela_manutencao   text,
    tags                text[] NOT NULL DEFAULT '{}',
    observacoes         text,
    atualizado_por      uuid REFERENCES app.usuario(id) ON DELETE SET NULL,
    criado_em           timestamptz NOT NULL DEFAULT now(),
    atualizado_em       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cliente_id, host_id),
    CONSTRAINT ativo_contexto_host_cliente_fk
        FOREIGN KEY (host_id, cliente_id)
        REFERENCES vm.host (id, cliente_id)
        ON DELETE CASCADE,
    CONSTRAINT ativo_contexto_ambiente_valido CHECK (
        ambiente IS NULL OR ambiente IN (
            'producao',
            'homologacao',
            'desenvolvimento',
            'laboratorio',
            'corporativo',
            'outro'
        )
    ),
    CONSTRAINT ativo_contexto_criticidade_valida CHECK (
        criticidade_negocio IS NULL OR criticidade_negocio IN (
            'critica', 'alta', 'media', 'baixa'
        )
    ),
    CONSTRAINT ativo_contexto_textos_validos CHECK (
        char_length(coalesce(equipe_responsavel, '')) <= 120
        AND char_length(coalesce(servico_negocio, '')) <= 160
        AND char_length(coalesce(unidade_negocio, '')) <= 120
        AND char_length(coalesce(janela_manutencao, '')) <= 200
        AND char_length(coalesce(observacoes, '')) <= 2000
    ),
    CONSTRAINT ativo_contexto_tags_validas CHECK (
        cardinality(tags) <= 20
    )
);

CREATE INDEX IF NOT EXISTS ativo_contexto_cliente_prioridade_idx
    ON app.ativo_contexto (
        cliente_id,
        criticidade_negocio,
        ambiente,
        exposto_internet
    );

CREATE INDEX IF NOT EXISTS ativo_contexto_responsavel_idx
    ON app.ativo_contexto (cliente_id, responsavel_id)
    WHERE responsavel_id IS NOT NULL;

COMMIT;
