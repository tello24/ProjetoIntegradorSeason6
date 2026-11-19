# Jira por empresa

Cada empresa cadastra sua própria conexão em **Integração Jira** (`/admin/jira`).
Somente o administrador pode consultar/alterar o cadastro, testar e ativar a conexão.
O cliente é determinado pela sessão autenticada, nunca por um campo enviado pelo navegador.
Administradores, gestores e analistas podem criar tickets; Visualizadores apenas leem vínculos.

## Preparação do servidor

- Aplicar as migrations, incluindo `010_jira_tenants.sql` (o Compose aplica automaticamente).
- Configurar `INTEGRATION_ENCRYPTION_KEYS` com uma chave Fernet exclusiva, gerada localmente.
  `npm run setup` já gera essa chave para instalações novas; não sobrescreve `.env` existente.
- Manter `JIRA_CONNECTIONS_ENABLED=true` para permitir conexões; `false` bloqueia chamadas externas.
- Configurar `APP_PUBLIC_URL` com o endereço da aplicação e `JIRA_TIMEOUT_SECONDS` (padrão 20).
- Usar HTTPS em produção. Não compartilhar tokens, `.env` ou backups no Git.

As antigas variáveis `TICKET_PROVIDER`, `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`,
`JIRA_PROJECT_KEY`, `JIRA_ISSUE_TYPE` e `JIRA_INCLUDE_ASSET_DETAILS` não ativam o cadastro
por empresa. Não há reutilização automática de uma credencial global entre clientes.

Os tokens ficam criptografados no PostgreSQL, com conteúdo vinculado ao identificador da
empresa. A chave de criptografia permanece no servidor e deve ter backup seguro separado.
Sem ela, restaurar apenas o banco não recupera as credenciais. A API nunca devolve o token salvo.
Para rotação, coloque a chave nova primeiro e mantenha as antigas separadas por vírgula;
salvar novamente cada cadastro recifra seu token. Não remova uma chave antiga antes de
recifrar todos os cadastros e considerar os backups que ainda dependem dela.

## Cadastro e ativação

1. Informar o site `https://empresa.atlassian.net`, e-mail da conta de integração, token,
   chave do projeto e nome exato ou ID do tipo de item. Deixar token vazio mantém o existente.
2. Para token com escopos, informar também o Cloud ID. O conector usa o gateway oficial e
   confere se o Cloud ID corresponde ao site cadastrado.
3. Escolher se IP/FQDN conhecidos podem ir no ticket. Revisar também textos livres na prévia;
   a omissão de identificadores conhecidos não garante anonimização de todo texto arbitrário.
4. Salvar, testar e ativar. Salvar desativa até novo teste. O teste verifica conta, permissões
   e campos do tipo, sem criar itens. Um teste bem-sucedido deve ter menos de uma hora na ativação.

A conta precisa consultar o projeto e criar itens com descrição e etiquetas. Esta versão
não mapeia campos personalizados obrigatórios sem valor padrão; o teste bloqueia esses tipos.
São aceitos Jira Cloud e tipos comuns, não subtarefas. Jira Data Center não é suportado.
Tokens com escopos precisam permitir os endpoints de identidade, permissões, metadados,
criação e busca utilizados; a configuração efetiva é verificada no teste de conexão.

## Criação e falhas

No detalhe da vulnerabilidade: **Revisar ticket no Jira → Confirmar envio ao Jira**.
A prévia contém o destino, severidade, score, CVEs, contexto operacional e plano já salvo.
Nenhuma geração de IA é disparada. Responsável, prazo e etapa são texto contextual;
não atribuem usuários nem alteram o workflow do Jira. Não existe sincronização bidirecional.

A confirmação valida uma impressão digital da prévia e reserva o vínculo antes da chamada
externa. Cliques concorrentes não enviam outra criação para o mesmo tratamento.

- `creating`: criação reservada; depois de 120 segundos é possível verificar o resultado.
- `created`: chave e link confirmados.
- `failed`: rejeição conhecida ou falha antes do envio; nova tentativa exige prévia e confirmação.
- `uncertain`: envio pode ter ocorrido; nova criação bloqueada. **Verificar ticket no Jira**
  apenas pesquisa a etiqueta exclusiva do tratamento. Nenhum resultado ou múltiplos resultados
  mantêm o bloqueio. A busca pode demorar para refletir um item recém-criado.

Não existe promessa de entrega exatamente uma vez em um serviço externo. Tentativas legadas
sem destino confirmado exigem conferência manual. Sites/projetos com vínculos existentes não
podem ser trocados pelo formulário; isso exige uma migração planejada. Desativar preserva os
vínculos. Chamadas em andamento podem terminar mesmo após a desativação.

URLs externas são restritas a HTTPS em sites Jira Cloud; redirecionamentos não são seguidos.
Erros usam mensagens locais, sem devolver respostas brutas do provedor ou credenciais.

## Verificação

Testes de API usam PostgreSQL isolado e Jira simulado: duas empresas, criptografia, permissões,
prévia, repetição de cliques, erro incerto e recuperação do vínculo. Testes de navegador usam
dados fictícios. A validação real permanece pendente até uma empresa cadastrar seu Jira e
autorizar um ticket de homologação.

Referências: [API de itens e metadados](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/),
[busca JQL](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/),
[tokens Atlassian](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)
e [Fernet](https://cryptography.io/en/latest/fernet/).
