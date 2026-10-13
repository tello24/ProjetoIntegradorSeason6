BEGIN;

ALTER TABLE app.usuario_cliente
    ADD COLUMN IF NOT EXISTS ativo boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS atualizado_em timestamptz NOT NULL DEFAULT now();

ALTER TABLE app.usuario_cliente
    DROP CONSTRAINT IF EXISTS usuario_cliente_papel_valido;

ALTER TABLE app.usuario_cliente
    ADD CONSTRAINT usuario_cliente_papel_valido
        CHECK (papel IN ('administrador', 'gestor', 'analista', 'visualizador'));

CREATE INDEX IF NOT EXISTS usuario_cliente_acesso_idx
    ON app.usuario_cliente (cliente_id, ativo, papel);

COMMIT;
