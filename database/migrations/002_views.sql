BEGIN;

CREATE OR REPLACE VIEW vm.vw_scan_lista AS
SELECT
    s.id,
    s.cliente_id,
    s.nome,
    s.scanner,
    s.status,
    count(DISTINCT sh.host_id)::integer AS ativos,
    count(a.id) FILTER (WHERE a.severidade > 0)::integer AS vulnerabilidades,
    s.iniciado_em,
    s.concluido_em,
    s.importado_em
FROM vm.scan s
LEFT JOIN vm.scan_host sh ON sh.scan_id = s.id
LEFT JOIN vm.achado a ON a.scan_id = s.id AND a.host_id = sh.host_id
GROUP BY s.id;

CREATE OR REPLACE VIEW vm.vw_scan_mais_recente AS
SELECT ranked.*
FROM (
    SELECT
        s.*,
        row_number() OVER (
            PARTITION BY s.cliente_id, s.escopo_chave
            ORDER BY s.concluido_em DESC NULLS LAST, s.importado_em DESC, s.id DESC
        ) AS ordem
    FROM vm.scan s
    WHERE s.status = 'concluido'
) ranked
WHERE ranked.ordem = 1;

CREATE OR REPLACE VIEW vm.vw_achado AS
SELECT
    a.id,
    s.cliente_id,
    a.scan_id,
    a.host_id,
    h.endereco,
    sh.fqdn,
    sh.sistema_operacional,
    sh.credenciado,
    a.plugin_id,
    p.nome AS titulo,
    p.familia,
    p.sinopse,
    p.descricao,
    p.solucao,
    coalesce(cves.cves, ARRAY[]::text[]) AS cves,
    a.protocolo,
    a.porta,
    a.servico,
    a.severidade,
    a.risco,
    a.cvss2,
    a.cvss3,
    a.cvss4,
    a.cvss3_vetor,
    a.vpr,
    a.epss,
    a.exploravel,
    a.maturidade_exploit,
    a.idade_vuln,
    a.saida_plugin,
    s.iniciado_em AS descoberto_em,
    s.concluido_em AS observado_em
FROM vm.achado a
JOIN vm.scan s ON s.id = a.scan_id
JOIN vm.host h ON h.id = a.host_id
JOIN vm.scan_host sh ON sh.scan_id = a.scan_id AND sh.host_id = a.host_id
JOIN vm.plugin p ON p.plugin_id = a.plugin_id
LEFT JOIN LATERAL (
    SELECT array_agg(pc.cve ORDER BY pc.cve) AS cves
    FROM vm.plugin_cve pc
    WHERE pc.plugin_id = a.plugin_id
) cves ON true;

CREATE OR REPLACE VIEW vm.vw_achado_atual AS
SELECT a.*
FROM vm.vw_achado a
JOIN vm.vw_scan_mais_recente s ON s.id = a.scan_id
WHERE a.severidade > 0;

CREATE OR REPLACE VIEW vm.vw_dashboard_resumo AS
SELECT
    s.cliente_id,
    count(DISTINCT sh.host_id)::integer AS ativos,
    count(a.id) FILTER (WHERE a.severidade > 0)::integer AS vulnerabilidades_abertas,
    count(a.id) FILTER (WHERE a.severidade = 4)::integer AS criticas,
    count(a.id) FILTER (WHERE a.severidade = 3)::integer AS altas,
    count(a.id) FILTER (WHERE a.severidade = 2)::integer AS medias,
    count(a.id) FILTER (WHERE a.severidade = 1)::integer AS baixas,
    least(
        100,
        coalesce(
            round(
                sum(
                    CASE a.severidade
                        WHEN 4 THEN 10
                        WHEN 3 THEN 5
                        WHEN 2 THEN 2
                        WHEN 1 THEN 1
                        ELSE 0
                    END
                )::numeric / greatest(count(DISTINCT sh.host_id), 1)
            ),
            0
        )
    )::integer AS pontuacao_risco
FROM vm.vw_scan_mais_recente s
LEFT JOIN vm.scan_host sh ON sh.scan_id = s.id
LEFT JOIN vm.achado a ON a.scan_id = s.id AND a.host_id = sh.host_id
GROUP BY s.cliente_id;

CREATE OR REPLACE VIEW vm.vw_host_risco AS
SELECT
    s.cliente_id,
    h.id AS host_id,
    h.endereco,
    sh.fqdn,
    sh.sistema_operacional,
    sh.credenciado,
    count(a.id) FILTER (WHERE a.severidade > 0)::integer AS total,
    count(a.id) FILTER (WHERE a.severidade = 4)::integer AS criticas,
    count(a.id) FILTER (WHERE a.severidade = 3)::integer AS altas,
    sum(
        CASE a.severidade
            WHEN 4 THEN 10
            WHEN 3 THEN 5
            WHEN 2 THEN 2
            WHEN 1 THEN 1
            ELSE 0
        END
    )::integer AS risco
FROM vm.vw_scan_mais_recente s
JOIN vm.scan_host sh ON sh.scan_id = s.id
JOIN vm.host h ON h.id = sh.host_id
LEFT JOIN vm.achado a ON a.scan_id = s.id AND a.host_id = h.id
GROUP BY s.cliente_id, h.id, sh.fqdn, sh.sistema_operacional, sh.credenciado;

COMMIT;
