# Diagnóstico local do PI

## Primeiro acesso em outro computador

O Git transporta código, não o `.env`, os volumes do PostgreSQL ou as contas locais.
Instale/abra Docker Desktop e, com Node.js 24+, execute `npm run setup` na raiz do projeto.
O comando cria `.env` com segredo de sessão, senha administrativa e senha de banco aleatórios;
a URL do banco é preenchida com a mesma senha. Se `.env` já existir, ele fica intacto.
Não é necessário instalar pacotes npm e nenhuma conexão externa é feita. As credenciais
não aparecem no terminal: consulte a conta inicial no próprio `.env` local.

Em sistemas POSIX, o arquivo novo é criado com permissão `0600`; no Windows, proteja
também a pasta por meio das permissões da sua conta. O comando não altera arquivos existentes.

Como alternativa manual, duplique `.env.example` como `.env` **somente se ainda não
existir**, escolha um segredo próprio e preencha a conta inicial. A senha inicial precisa
ter pelo menos 12 caracteres. `APP_ENV=development` habilita o bootstrap local.

No Compose padrão:

```dotenv
APP_ENV=development
API_CORS_ORIGINS=["http://localhost:3000"]
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
INTERNAL_API_URL=http://api:8000/api/v1
APP_PUBLIC_URL=http://localhost:3000
AI_PROVIDER=disabled
TICKET_PROVIDER=disabled
```

Mantenha as credenciais de `DATABASE_URL` consistentes com `POSTGRES_DB`,
`POSTGRES_USER` e `POSTGRES_PASSWORD`. O host do banco é `database` dentro do Compose.
Use exatamente `http://localhost:3000` no navegador. Depois:

```bash
docker compose up -d --build
docker compose ps -a
```

`database`, `api` e `web` devem estar em execução. `migrations` com saída 0 é esperado.
A API passa a expor `/api/v1/health/ready`, que verifica conexão e parte do esquema
necessário ao login e à aplicação. Ela retorna apenas estados genéricos, nunca erros SQL,
segredos, nomes de usuários ou dados de clientes. Não é uma auditoria completa do banco.

## Verificação assistida

Com Node.js 24+ instalado, no terminal da pasta principal, tanto no macOS/Linux quanto
no PowerShell do Windows:

```bash
npm run doctor
```

O comando usa apenas a biblioteca padrão do Node, sem precisar de `npm install`.
Se o PowerShell bloquear `npm.ps1`, use `npm.cmd run doctor` ou `node scripts/doctor.mjs`;
não é necessário desativar políticas de segurança do computador.

O diagnóstico é somente leitura: não cria `.env`, não reinicia contêineres, não executa
migrações, não apaga volumes e não envia senhas de login. Checagens de HTTP só são feitas
em endereços de loopback, com tempo limite e sem seguir redirecionamentos. Não chama IA.

Ele verifica:

- presença e coerência das principais variáveis de configuração;
- seleção do provedor de IA, presença da chave e faixas de timeout/tokens, sem chamada paga;
- formato de CORS, URL pública e URL interna usadas pelo navegador e servidor;
- acesso ao Docker/Compose e estado dos quatro serviços do Compose padrão;
- resposta de prontidão da API, preflight CORS e acesso à página de login.

Erros resultam em código de saída 1; avisos isolados não. Para saída estruturada:

```bash
npm run doctor -- --json
```

O diagnóstico é voltado ao Compose local padrão. Configurações remotas, arquivos de override,
interpolação complexa de variáveis e redes corporativas exigem análise específica.
Uma resposta de prontidão não confirma que todas as consultas funcionam ou que a senha está
correta. O teste de CORS utiliza APP_PUBLIC_URL; confira também a URL realmente aberta.

## Quando o diagnóstico não bastar

```bash
docker compose logs --tail=60 api migrations database
```

Revise esses logs antes de compartilhar: ao contrário da saída limitada do doctor, eles
podem conter informações sensíveis. Nunca envie o `.env` completo ou chaves de API.
Não use `docker compose down -v` como tentativa genérica de corrigir login: isso pode
apagar o banco. Se a senha do PostgreSQL foi alterada depois da criação do volume,
alterar o `.env` não atualiza a senha já armazenada no banco.

Depois de corrigir configurações, recrie os serviços com `docker compose up -d --build`.
No primeiro início, `BOOTSTRAP_ADMIN_EMAIL` e `BOOTSTRAP_ADMIN_PASSWORD` definem a conta
local; em development, o bootstrap também pode atualizar essa senha ao reiniciar a API.

Se mudou somente a chave de IA, recrie apenas a API com
`docker compose up -d --no-deps --force-recreate api`. Atualizar o navegador não recarrega
as variáveis do servidor. O guia [de IA](ai.md) descreve os códigos de erro e o cache.

## Construção das imagens

Os arquivos `.dockerignore` permitem apenas fontes e manifestos necessários ao build;
excluem `.env`, chaves, exportações `.nessus`, caches e dependências locais. Isso não
substitui revisar o que entra no Git nem protege arquivos montados por volume em execução.
O frontend usa `npm ci` para instalar a árvore registrada em `package-lock.json`, falhando
se o manifesto estiver inconsistente, em vez de resolver versões diferentes silenciosamente.

Referências: [contexto de build do Docker](https://docs.docker.com/build/concepts/context/)
e [instalação com npm ci](https://docs.npmjs.com/cli/v11/commands/npm-ci/).
