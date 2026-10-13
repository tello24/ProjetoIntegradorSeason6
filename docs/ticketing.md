# Integração com tickets

O WVM possui um conector inicial para Jira Cloud. A criação é manual, ocorre a partir do
detalhe da vulnerabilidade e grava o vínculo no PostgreSQL antes e depois da chamada externa.
Uma restrição única por vulnerabilidade e provedor impede tickets duplicados em cliques
concorrentes.

## Configuração

```env
TICKET_PROVIDER=jira
JIRA_BASE_URL=https://sua-empresa.atlassian.net
JIRA_EMAIL=conta-de-servico@empresa.com
JIRA_API_TOKEN=token-da-conta-de-servico
JIRA_PROJECT_KEY=SEC
JIRA_ISSUE_TYPE=Task
JIRA_TIMEOUT_SECONDS=20
JIRA_INCLUDE_ASSET_DETAILS=false
APP_PUBLIC_URL=https://wvm.empresa.com
```

O token precisa existir apenas no backend. Ele nunca é enviado ao navegador nem salvo no
banco. Por padrão, IP e FQDN ficam fora do Jira. Caso o Jira pertença ao mesmo ambiente de
confiança e esses dados sejam necessários à operação, ative `JIRA_INCLUDE_ASSET_DETAILS`.

O ticket recebe severidade, WVM Score, CVSS, CVEs, exposição, link para o WVM e o plano de
IA salvo. Quando ainda não existe análise de IA, usa a recomendação original do scanner.

Estados locais:

- `creating`: solicitação reservada e chamada em andamento;
- `created`: ticket criado e link persistido;
- `failed`: chamada falhou e pode ser repetida pelo usuário.

Uma futura integração (ServiceNow, Azure DevOps etc.) deve implementar um cliente próprio e
reaproveitar o mesmo fluxo de reserva, auditoria e persistência.
