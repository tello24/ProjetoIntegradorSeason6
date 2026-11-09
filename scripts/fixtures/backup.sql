-- Synthetic data only. This fixture must never run against an application database.
INSERT INTO vm.cliente (nome, slug) VALUES ('BACKUP FICTICIO', 'backup-test');
INSERT INTO app.usuario (id, nome, email, senha_hash)
VALUES ('00000000-0000-0000-0000-000000000001', 'Usuário fictício',
        'backup-test@example.com', 'synthetic-hash-not-a-real-login');
INSERT INTO app.usuario_cliente (usuario_id, cliente_id, papel)
VALUES ('00000000-0000-0000-0000-000000000001', 1, 'administrador');
INSERT INTO vm.scan (cliente_id, nome, escopo_chave, status, chave_origem)
VALUES (1, 'SCAN FICTICIO BACKUP', 'backup-test-scope', 'concluido', 'backup-test-source');
INSERT INTO vm.host (cliente_id, endereco) VALUES (1, '192.0.2.123');
INSERT INTO vm.scan_host (scan_id, host_id, fqdn) VALUES (1, 1, 'backup-test.example.com');
INSERT INTO vm.plugin (plugin_id, nome) VALUES (900001, 'Plugin fictício');
INSERT INTO vm.achado (scan_id, host_id, plugin_id, severidade) VALUES (1, 1, 900001, 3);
INSERT INTO app.vulnerabilidade_tratamento (
    id, cliente_id, host_id, plugin_id, status, responsavel_id, prazo,
    observacao_atual, ultimo_scan_id, ultimo_achado_id, primeiro_detectado_em,
    ultimo_detectado_em
) VALUES (
    '00000000-0000-0000-0000-000000000002', 1, 1, 900001, 'in_progress',
    '00000000-0000-0000-0000-000000000001', '2030-01-15',
    'Nota fictícia preservada no backup: acentuação e histórico.', 1, 1, now(), now()
);
INSERT INTO app.vulnerabilidade_analise_ia (
    cliente_id, tratamento_id, geracao, provedor, modelo, versao_prompt,
    assinatura_entrada, conteudo, tokens_entrada, tokens_saida, tokens_total, custo_estimado_usd
) VALUES (
    1, '00000000-0000-0000-0000-000000000002', 1, 'anthropic', 'synthetic-model',
    'synthetic-v1', repeat('a', 64), '{"why_it_matters":"Resposta fictícia já salva."}',
    10, 20, 30, 0.0001
);
INSERT INTO app.vulnerabilidade_ticket (
    cliente_id, tratamento_id, provedor, status, chave_externa, url_externa, resumo
) VALUES (
    1, '00000000-0000-0000-0000-000000000002', 'jira', 'created', 'DEMO-1',
    'https://example.com/DEMO-1', 'Ticket fictício, sem integração externa'
);
INSERT INTO app.evento_auditoria (cliente_id, acao, recurso, recurso_id, detalhes)
VALUES (1, 'backup.synthetic_fixture', 'scan', '1', '{"synthetic":true}');
