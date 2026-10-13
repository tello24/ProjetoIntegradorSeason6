BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS vm;

CREATE TABLE vm.cliente (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nome            text NOT NULL,
    slug            text NOT NULL UNIQUE,
    ativo           boolean NOT NULL DEFAULT true,
    criado_em       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.usuario (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    nome            text NOT NULL,
    email           text NOT NULL,
    senha_hash      text NOT NULL,
    ativo           boolean NOT NULL DEFAULT true,
    criado_em       timestamptz NOT NULL DEFAULT now(),
    atualizado_em   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT usuario_email_normalizado UNIQUE (email),
    CONSTRAINT usuario_email_lowercase CHECK (email = lower(email))
);

CREATE TABLE app.usuario_cliente (
    usuario_id      uuid NOT NULL REFERENCES app.usuario(id) ON DELETE CASCADE,
    cliente_id      bigint NOT NULL REFERENCES vm.cliente(id) ON DELETE CASCADE,
    papel           text NOT NULL DEFAULT 'analista',
    criado_em       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (usuario_id, cliente_id),
    CONSTRAINT usuario_cliente_papel_valido
        CHECK (papel IN ('administrador', 'analista', 'visualizador'))
);

CREATE TABLE vm.scan (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cliente_id      bigint NOT NULL REFERENCES vm.cliente(id) ON DELETE RESTRICT,
    nome            text NOT NULL,
    scanner         text NOT NULL DEFAULT 'nessus',
    politica        text,
    alvos           text,
    escopo_chave    text NOT NULL,
    status          text NOT NULL DEFAULT 'recebido',
    chave_origem    text NOT NULL,
    arquivo         text,
    iniciado_em     timestamptz,
    concluido_em    timestamptz,
    importado_em    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT scan_status_valido CHECK (
        status IN ('recebido', 'validando', 'processando', 'concluido', 'falhou')
    ),
    CONSTRAINT scan_origem_por_cliente UNIQUE (cliente_id, chave_origem)
);

CREATE INDEX scan_cliente_importado_idx
    ON vm.scan (cliente_id, importado_em DESC);
CREATE INDEX scan_cliente_escopo_conclusao_idx
    ON vm.scan (cliente_id, escopo_chave, concluido_em DESC NULLS LAST);

CREATE TABLE vm.importacao (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cliente_id      bigint NOT NULL REFERENCES vm.cliente(id) ON DELETE RESTRICT,
    usuario_id      uuid REFERENCES app.usuario(id) ON DELETE SET NULL,
    scan_id         bigint REFERENCES vm.scan(id) ON DELETE SET NULL,
    arquivo         text NOT NULL,
    tamanho_bytes   bigint NOT NULL DEFAULT 0,
    status          text NOT NULL DEFAULT 'recebido',
    linhas          integer NOT NULL DEFAULT 0,
    achados         integer NOT NULL DEFAULT 0,
    mensagem        text,
    iniciado_em     timestamptz NOT NULL DEFAULT now(),
    concluido_em    timestamptz,
    CONSTRAINT importacao_status_valido CHECK (
        status IN ('recebido', 'validando', 'processando', 'concluido', 'falhou')
    ),
    CONSTRAINT importacao_tamanho_nao_negativo CHECK (tamanho_bytes >= 0)
);

CREATE INDEX importacao_cliente_inicio_idx
    ON vm.importacao (cliente_id, iniciado_em DESC);

CREATE TABLE vm.host (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cliente_id      bigint NOT NULL REFERENCES vm.cliente(id) ON DELETE CASCADE,
    endereco        text NOT NULL,
    criado_em       timestamptz NOT NULL DEFAULT now(),
    atualizado_em   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT host_endereco_por_cliente UNIQUE (cliente_id, endereco)
);

CREATE TABLE vm.scan_host (
    scan_id         bigint NOT NULL REFERENCES vm.scan(id) ON DELETE CASCADE,
    host_id         bigint NOT NULL REFERENCES vm.host(id) ON DELETE CASCADE,
    fqdn            text,
    netbios         text,
    sistema_operacional text,
    mac             text,
    tipo_sistema    text,
    credenciado     boolean NOT NULL DEFAULT false,
    observado_em    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_id, host_id)
);

CREATE INDEX scan_host_host_idx ON vm.scan_host (host_id, scan_id);

CREATE TABLE vm.plugin (
    plugin_id       bigint PRIMARY KEY,
    nome            text NOT NULL,
    familia         text,
    sinopse         text,
    descricao       text,
    solucao         text,
    referencias     text,
    cwe             text,
    publicado_em    date,
    modificado_em   date,
    atualizado_em   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE vm.plugin_cve (
    plugin_id       bigint NOT NULL REFERENCES vm.plugin(plugin_id) ON DELETE CASCADE,
    cve             text NOT NULL,
    PRIMARY KEY (plugin_id, cve)
);

CREATE INDEX plugin_cve_cve_idx ON vm.plugin_cve (cve);

CREATE TABLE vm.achado (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id         bigint NOT NULL REFERENCES vm.scan(id) ON DELETE CASCADE,
    host_id         bigint NOT NULL REFERENCES vm.host(id) ON DELETE CASCADE,
    plugin_id       bigint NOT NULL REFERENCES vm.plugin(plugin_id) ON DELETE RESTRICT,
    protocolo       text NOT NULL DEFAULT 'tcp',
    porta           integer NOT NULL DEFAULT 0,
    servico         text,
    severidade      smallint NOT NULL,
    risco           text,
    cvss2           numeric(4, 1),
    cvss3           numeric(4, 1),
    cvss4           numeric(4, 1),
    cvss3_vetor     text,
    vpr             numeric(4, 1),
    epss            numeric(8, 7),
    exploravel      boolean NOT NULL DEFAULT false,
    maturidade_exploit text,
    idade_vuln      integer,
    saida_plugin    text,
    criado_em       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT achado_severidade_valida CHECK (severidade BETWEEN 0 AND 4),
    CONSTRAINT achado_porta_valida CHECK (porta BETWEEN 0 AND 65535),
    CONSTRAINT achado_unico_por_scan
        UNIQUE (scan_id, host_id, plugin_id, protocolo, porta)
);

CREATE INDEX achado_scan_severidade_idx ON vm.achado (scan_id, severidade DESC);
CREATE INDEX achado_host_idx ON vm.achado (host_id);
CREATE INDEX achado_plugin_idx ON vm.achado (plugin_id);

CREATE TABLE app.evento_auditoria (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cliente_id      bigint REFERENCES vm.cliente(id) ON DELETE SET NULL,
    usuario_id      uuid REFERENCES app.usuario(id) ON DELETE SET NULL,
    acao            text NOT NULL,
    recurso         text NOT NULL,
    recurso_id      text,
    detalhes        jsonb NOT NULL DEFAULT '{}'::jsonb,
    criado_em       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX evento_auditoria_cliente_data_idx
    ON app.evento_auditoria (cliente_id, criado_em DESC);

COMMIT;
