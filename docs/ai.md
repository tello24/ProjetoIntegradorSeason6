# IA de explicação e remediação

## Fluxo

1. A interface consulta a análise atual no PostgreSQL ao abrir a vulnerabilidade.
2. Se ela já existe, o conteúdo salvo é exibido e nenhuma API externa é chamada.
3. Se não existe, um analista ou administrador pode autorizar a primeira geração.
4. O backend reúne a evidência específica do plugin, contexto do ativo, CVSS, VPR, EPSS e
   explorabilidade. O texto é limitado e um filtro remove padrões de IPs, hostnames, URLs e
   e-mails antes da requisição. Esse filtro não garante anonimização completa de texto livre;
   use apenas dados cujo envio ao provedor tenha sido autorizado pela organização.
5. Regras determinísticas e fatos extraídos pela aplicação acompanham o pedido. Por exemplo, se
   os pacotes corrigidos já estão instalados e o plugin informa reboot pendente, um plano que
   recomende reinstalação ou nova atualização é rejeitado.
6. O provedor retorna um objeto estruturado com a explicação e o plano de correção. No Claude,
   usamos a saída JSON validada nativamente pelo schema em vez de simular uma chamada de
   ferramenta.
7. Limites de apresentação que o schema do provedor não consegue impor são normalizados
   localmente, sem realizar uma segunda chamada paga.
8. A lista de evidências exibida é derivada pelo backend, não inventada pelo modelo. As fontes
   oficiais são filtradas por HTTPS e por domínios confiáveis antes de aparecerem na tela.
9. Conteúdo, provedor, modelo, tokens, custo estimado e versão do prompt são salvos.
10. Uma nova versão exige confirmação e perfil de administrador. A versão anterior é preservada.

O bloqueio transacional por vulnerabilidade impede duas gerações simultâneas para o mesmo
achado. Se o provedor falhar durante uma regeneração, a análise atual não é substituída.

## Conhecimento e fontes

O assistente não é tratado como autoridade única. A ordem de confiança enviada ao modelo é:

1. evidência específica do plugin e inventário observado no scan;
2. advisory e documentação oficial do fornecedor;
3. metadados do scanner;
4. NVD e CVSS como classificação complementar.

A importação preserva `plugin_output` e os links de `see_also` do Nessus. A aplicação também cria
links verificáveis para o plugin da Tenable, advisory RLSA/RHSA e registros CVE no NVD. Para
Enterprise Linux e kernel, o conhecimento local inclui as práticas documentadas por Red Hat e
Rocky Linux: validar pacotes e kernel em execução, instalar atualizações com DNF quando necessário,
reiniciar para carregar o novo kernel, conferir o kernel padrão e nunca remover diretamente o
kernel em execução.

O conjunto inicial também cobre os outros grupos relevantes do scan de demonstração:

- Grafana: advisory oficial por CVE, guia de upgrade, método de instalação, backup de banco,
  configuração e plugins, compatibilidade e rollback dependente de migração;
- TLS, certificados e SSH: ponto real de terminação, cadeia/SAN/trust store, dependência de clientes,
  teste gradual e preservação de acesso administrativo;
- scans não credenciados: obrigação de confirmar localmente produto, versão e configuração antes de
  sugerir qualquer mudança.

Fontes-base:

- [Tenable Nessus Plugins](https://www.tenable.com/plugins/nessus/)
- [Rocky Linux Errata](https://docs.rockylinux.org/latest/teams/rel_eng/errata/)
- [Red Hat — gerenciamento e atualização do kernel](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_monitoring_and_updating_the_kernel/assembly_the-linux-kernel_managing-monitoring-and-updating-the-kernel)
- [Red Hat — atualização com DNF](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_software_with_the_dnf_tool/assembly_updating-rhel-9-content_managing-software-with-the-dnf-tool)
- [NVD](https://nvd.nist.gov/vuln)
- [Grafana Labs — Security Advisories](https://grafana.com/security/security-advisories/)
- [Grafana Labs — Upgrade Guide](https://grafana.com/docs/grafana/latest/upgrade-guide/)
- [NIST SP 800-52 Rev. 2 — TLS](https://csrc.nist.gov/pubs/sp/800/52/r2/final)

Os links são fornecidos para conferência humana; o modelo não navega neles durante a geração e é
proibido de afirmar que leu uma página. Esse desenho evita conteúdo web mutável ou malicioso no
prompt. Para ampliar o conhecimento no futuro, deve-se adicionar uma camada RAG versionada que
baixe, valide, registre data e hash e aprove cada documento antes do uso.

## Configuração

As únicas opções aceitas em `AI_PROVIDER` são:

- `disabled`: não chama uma API externa e usa o plano-base local;
- `anthropic`: usa `ANTHROPIC_API_KEY` e `ANTHROPIC_MODEL`;
- `openai`: usa `OPENAI_API_KEY` e `OPENAI_MODEL`.

O Claude Haiku 4.5 é configurado assim no `.env` local:

```dotenv
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=cole-a-chave-somente-aqui
ANTHROPIC_WORKSPACE_ID=wrkspc_se_sua_chave_exigir
ANTHROPIC_MODEL=claude-haiku-4-5
```

Chaves pessoais ou de serviço com acesso a múltiplos workspaces exigem
`ANTHROPIC_WORKSPACE_ID`. O identificador começa com `wrkspc_` e pode ser encontrado no Claude
Console em **Settings → Workspaces**. Uma chave criada já vinculada a um único workspace pode
deixar essa variável vazia.

Para alternar para OpenAI:

```dotenv
AI_PROVIDER=openai
OPENAI_API_KEY=cole-a-chave-somente-aqui
OPENAI_MODEL=gpt-5.4-mini
```

Após alterar o `.env`, reconstrua somente a API:

```bash
docker compose up -d --build api
```

Nunca coloque uma chave em variável `NEXT_PUBLIC_`, no frontend, em captura de tela ou no Git.
As tarifas por milhão de tokens ficam configuráveis porque os fornecedores podem mudar preços.
Atualize essas variáveis quando necessário para manter a estimativa registrada correta.

## Versionamento e custos

### Respostas interrompidas pelo limite de saída

O padrão desde 09/11/2026 é `AI_MAX_OUTPUT_TOKENS=4096`. Esse valor é o teto por
requisição, não uma meta de consumo nem um orçamento mensal. O custo estimado das
análises salvas continua usando o consumo informado pelo provedor, não esse teto.
Respostas efetivamente maiores podem custar mais; 4096 não garante que todo pedido caiba.

O prompt `2026-11-09-v1` pede respostas objetivas, com meta de até 650 palavras nos
valores do JSON, limites sugeridos por seção e agrupamento de ações comuns a várias CVEs.
Essas orientações não removem verificações, cautelas, rollback ou validação técnica.
Não são limites de tokens impostos pelo modelo nem garantia de tamanho da resposta.

Em instalações existentes, atualizar **somente** `AI_MAX_OUTPUT_TOKENS` e
`AI_PROMPT_VERSION` no `.env` local; editar `.env.example` ou executar `git pull`
não substitui o `.env`. Recriar a API no mesmo projeto Compose carrega a configuração.
Não é necessário apagar o banco ou as análises existentes. A mudança de versão pode
marcar uma análise como antiga, mas ela continua sendo reutilizada sem regeneração
automática. Uma nova versão permanece sujeita à autorização explícita do administrador.

Se o Claude retornar `stop_reason=max_tokens`, a resposta continua sendo rejeitada,
mesmo que o trecho recebido tenha JSON válido. O sistema mantém o plano-base ou a
análise anterior, registra a falha e não repete a chamada automaticamente. A tentativa
pode ser cobrada pelo provedor. Depois do ajuste, uma nova tentativa deve ser manual.

`AI_PROMPT_VERSION` identifica a regra usada para produzir a resposta. Sempre que o conteúdo do
prompt mudar em produção, altere essa versão. A assinatura dos dados de entrada permite avisar
quando o scanner trouxe informações mais recentes sem gerar automaticamente outra cobrança.

O custo salvo é uma estimativa calculada com os tokens informados pelo provedor e as tarifas do
`.env`. A cobrança oficial continua sendo a apresentada pelo painel do fornecedor.
Uma tentativa processada e posteriormente rejeitada pela aplicação também pode consumir tokens no
provedor, mesmo sem produzir uma análise salva no histórico local.

## Diagnóstico de falhas em uma instalação clonada

### Painel administrativo local

Administradores podem abrir **Administração da IA** (`/admin/ai`). A página consulta apenas
`GET /api/v1/admin/ai/summary?days=30`, com períodos permitidos de 7, 30 ou 90 dias corridos.
Não testa a chave, não consulta saldo/fatura, não gera conteúdo e não altera configurações.
A API exige autenticação e papel administrador; métricas e eventos são filtrados pelo cliente
da sessão e a resposta usa `Cache-Control: private, no-store`.

A configuração exibida é a carregada pela API, não uma leitura do `.env` do navegador.
Somente a presença da chave/workspace é informada; seus valores nunca são enviados.
“Configurada” não significa que a conexão ou o faturamento funcionem.

O total de análises/tokens/custo inclui **todas as versões salvas** no intervalo, não apenas
as ativas. O agrupamento usa o provedor e modelo registrados na geração. Custos históricos
não são recalculados com as tarifas atuais. A última análise salva considera todo o histórico.
Os limites do intervalo são calculados em UTC na API; datas da tela usam `America/Sao_Paulo`.
O total monetário usa USD e até oito casas decimais para não ocultar pequenos consumos.

Tentativas que retornam plano-base passam a registrar `ai_analysis.failed` na auditoria,
com provedor, código permitido, indicador de regeneração e situação de custo. Não se salva
prompt, chave, resposta bruta nem texto de exceção. Bloqueios `disabled`/`missing_key` são
marcados como sem chamada externa; demais falhas têm **custo desconhecido**, nunca zero
inferido. Uma regeneração falha mantém intacta a análise anterior. Reutilizar uma análise
salva não cria evento de falha nem uma nova geração.

Mostramos até 20 falhas mais recentes e a contagem total no período. Esse registro começa
com esta versão: não reconstrói logs antigos nem garante captura de interrupções abruptas
do processo ou de falhas de gravação no banco. Ausência de registros não prova saúde do provedor.
O monitor não mede cache hits, não calcula economia, não concilia cobranças e não impõe orçamento.
Uso externo à instalação e tentativas com custo desconhecido podem constar na fatura oficial.

### Configuração de um clone

O Git não inclui `.env`, chave, créditos ou o banco de outro computador. Alterar somente
`.env.example` não configura a instalação. Crie/preencha `.env` e recrie a API; execute
`npm run doctor` para conferir as variáveis sem mostrar segredos ou fazer chamadas pagas.
O diagnóstico local não comprova a validade da chave ou o saldo.

A resposta de remediação inclui `error_code` e uma orientação segura:

| Código | O que verificar |
| --- | --- |
| `disabled` / `missing_key` | Provedor e chave no `.env`; API recriada. Nenhuma chamada foi feita. |
| `authentication` / `permission` | Validade da chave e permissões de workspace/modelo. |
| `billing` / `rate_limit` | Créditos, faturamento e limites no painel do provedor. |
| `timeout` / `connection` | Prazo, rede, proxy e certificados; não desativar TLS. |
| `model_not_found` / `request_rejected` | Modelo e compatibilidade dos parâmetros. |
| `output_limit` | Resposta cortada; revisar orçamento de tokens antes de tentar novamente. |
| `refusal` / `unsafe_response` / `invalid_response` | Contexto recusado ou resposta reprovada pela validação; revisar evidências. |
| `provider_unavailable` | Indisponibilidade temporária do provedor. |

Não há repetição automática. Após resolver a causa, analistas e administradores podem usar
**TENTAR GERAR ANÁLISE** no plano-base, com confirmação de possível consumo. O pedido usa a rota
normal de geração e respeita o cache; não precisa permissão de regenerar uma versão já salva.
Se uma regeneração falhar, a versão anterior permanece salva e a causa aparece na tela.
Os registros de falha contêm apenas provedor, código e status HTTP, não a resposta bruta ou a chave.

Referências do contrato Anthropic:
[erros da API](https://platform.claude.com/docs/en/api/errors) e
[saídas estruturadas](https://platform.claude.com/docs/en/build-with-claude/structured-outputs).
