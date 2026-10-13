BEGIN;

ALTER TABLE vm.scan_host
    ADD COLUMN IF NOT EXISTS bios_uuid text,
    ADD COLUMN IF NOT EXISTS cpes text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS confianca_sistema smallint,
    ADD COLUMN IF NOT EXISTS metodo_sistema text,
    ADD COLUMN IF NOT EXISTS protocolo_verificacao_local text,
    ADD COLUMN IF NOT EXISTS scan_iniciado_em timestamptz,
    ADD COLUMN IF NOT EXISTS scan_concluido_em timestamptz,
    ADD COLUMN IF NOT EXISTS ultimo_resultado_autenticado_em timestamptz,
    ADD COLUMN IF NOT EXISTS ultimo_resultado_nao_autenticado_em timestamptz,
    ADD COLUMN IF NOT EXISTS total_cves_patches integer,
    ADD COLUMN IF NOT EXISTS metadados jsonb NOT NULL DEFAULT '{}'::jsonb;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'scan_host_confianca_sistema_valida'
    ) THEN
        ALTER TABLE vm.scan_host
            ADD CONSTRAINT scan_host_confianca_sistema_valida
            CHECK (confianca_sistema BETWEEN -1 AND 100);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'scan_host_total_patches_valido'
    ) THEN
        ALTER TABLE vm.scan_host
            ADD CONSTRAINT scan_host_total_patches_valido
            CHECK (total_cves_patches >= 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'scan_host_metadados_objeto'
    ) THEN
        ALTER TABLE vm.scan_host
            ADD CONSTRAINT scan_host_metadados_objeto
            CHECK (jsonb_typeof(metadados) = 'object');
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS vm.scan_servico (
    scan_id         bigint NOT NULL,
    host_id         bigint NOT NULL,
    protocolo       text NOT NULL,
    porta           integer NOT NULL,
    servico         text,
    observado_em    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_id, host_id, protocolo, porta),
    CONSTRAINT scan_servico_host_scan_fk
        FOREIGN KEY (scan_id, host_id)
        REFERENCES vm.scan_host (scan_id, host_id)
        ON DELETE CASCADE,
    CONSTRAINT scan_servico_porta_valida CHECK (porta BETWEEN 1 AND 65535)
);

CREATE INDEX IF NOT EXISTS scan_servico_host_historico_idx
    ON vm.scan_servico (host_id, observado_em DESC);

COMMIT;
