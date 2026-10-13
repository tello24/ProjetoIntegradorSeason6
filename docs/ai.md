# IA de explicação e remediação

## Fluxo

1. A interface consulta a análise atual no PostgreSQL ao abrir a vulnerabilidade.
2. Se ela já existe, o conteúdo salvo é exibido e nenhuma API externa é chamada.
3. Se não existe, um analista ou administrador pode autorizar a primeira geração.
4. O backend reúne a evidência específica do plugin, contexto do ativo, CVSS, VPR, EPSS e
   explorabilidade. O texto é limitado e IPs, hostnames, URLs e e-mails são removidos antes da
   requisição.
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

`AI_PROMPT_VERSION` identifica a regra usada para produzir a resposta. Sempre que o conteúdo do
prompt mudar em produção, altere essa versão. A assinatura dos dados de entrada permite avisar
quando o scanner trouxe informações mais recentes sem gerar automaticamente outra cobrança.

O custo salvo é uma estimativa calculada com os tokens informados pelo provedor e as tarifas do
`.env`. A cobrança oficial continua sendo a apresentada pelo painel do fornecedor.
Uma tentativa processada e posteriormente rejeitada pela aplicação também pode consumir tokens no
provedor, mesmo sem produzir uma análise salva no histórico local.
