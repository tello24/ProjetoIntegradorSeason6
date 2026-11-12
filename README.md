# WVM — Wolf Vulnerability Management.

Aplicação interna em desenvolvimento.

## Estrutura

- `apps/web`: interface web em Next.js
- `apps/api`: API em FastAPI
- `database`: migrações e views do PostgreSQL
- `docs`: decisões técnicas do projeto
- `tests/fixtures`: amostras anonimizadas para testes

## Desenvolvimento local

1. Instale e abra o Docker Desktop.
2. Com Node.js 24+, execute `npm run setup` (não precisa de `npm install`). O comando cria
   `.env` com credenciais aleatórias **somente se o arquivo ainda não existir**.
3. Consulte a conta inicial no `.env`. Para habilitar IA, configure provedor e chave nesse
   arquivo; uma instalação nova começa com IA e Jira desativados.
4. Inicie os serviços com `docker compose up --build`.
5. Acesse a interface em `http://localhost:3000` e a documentação da API em `http://localhost:8000/docs`.

No primeiro início, o backend cria a organização e a conta local definidas no `.env`.
Use `BOOTSTRAP_ADMIN_EMAIL` e `BOOTSTRAP_ADMIN_PASSWORD` para entrar. Essa criação
automática só funciona quando `APP_ENV=development`.

Sem Node instalado no computador, crie `.env` a partir de `.env.example` manualmente,
apenas se ele ainda não existir, e troque `APP_SECRET_KEY`, `BOOTSTRAP_ADMIN_PASSWORD`
e a senha do banco (em `POSTGRES_PASSWORD` **e** `DATABASE_URL`). Não sobrescreva um
`.env` já configurado nem envie esse arquivo pelo Git. O setup não conecta serviços,
não chama IA e não altera o banco existente.

Para gerar um segredo local forte:

```bash
openssl rand -hex 32
```

## Primeiro fluxo funcional

1. Entre com a conta local.
2. Abra **Scans** e selecione **Importar scan**.
3. Envie uma exportação `.nessus`.
4. Acompanhe o processamento até o status **Concluído**.
5. Use o dashboard **Executivo** para risco e exposição ou o **Operacional** para acompanhar o funil de remediação, prazos e responsáveis.
6. Abra um ativo para consultar o **Asset 360**, incluindo contexto de negócio, cobertura,
   serviços, mudanças e evidências.
7. Abra um achado para definir etapa, responsável, prazo e observação de tratamento.
8. Abra **Relatórios** para acompanhar entradas, correções, reaberturas e backlog por mês.
9. Se o Jira estiver configurado, crie e abra o ticket diretamente no detalhe do achado.
10. Como administrador, abra **Acessos** para cadastrar a equipe e definir os perfis.
11. Em **Administração da IA**, acompanhe consumo por pessoa e use **Ver vulnerabilidades**
    para detalhar gerações, tokens e custo estimado no período. Consultar o painel não gasta IA.

Cada achado recebe um **WVM Score** transparente, pode ser aberto em uma visão técnica
detalhada e os scans do mesmo escopo podem ser comparados para identificar achados novos,
corrigidos, reabertos e persistentes. A fórmula e as faixas estão documentadas em
[`docs/neoscore.md`](docs/neoscore.md).

O contexto de negócio registra ambiente, criticidade, responsável, equipe, serviço e janela de
manutenção sem alterar o WVM Score. Administradores e gestores podem editar esses dados; todos
os perfis podem consultá-los. As mudanças ficam auditadas e os indicadores do inventário
destacam ausência de ownership, ativos críticos vulneráveis e produção sem scan credenciado.
Consulte [`docs/asset-business-context.md`](docs/asset-business-context.md).

O acompanhamento operacional permanece ligado à identidade técnica do achado entre os
scans. Alterações de etapa, responsável e prazo ficam registradas no histórico de auditoria,
e o dashboard consolida itens em correção, aguardando validação, atrasados ou sem responsável.
Os filtros globais de escopo e severidade atualizam todos os indicadores do recorte. O painel
de confiabilidade informa se os números estão apoiados em scans recentes, credenciados e sem
falhas de importação. A aparência pode ser clara, escura ou acompanhar o sistema operacional.
Quando um achado do scan anterior deixa de aparecer em um novo scan do mesmo escopo, o
sistema confirma a resolução automaticamente. Se ele voltar em um scan futuro, é reaberto
sem perder responsável, observações ou histórico. A validação é conservadora: scans de
escopos diferentes não encerram vulnerabilidades entre si.

O relatório mensal usa esse histórico auditável para comparar vulnerabilidades novas,
corrigidas e reabertas, reconstruir o backlog no fechamento de cada mês e deixar explícitos
os meses sem scan. O período pode ser filtrado por severidade, exportado em CSV ou impresso
como PDF pelo navegador.

Na página do achado, um analista ou administrador pode gerar uma explicação simples de **por que aquilo importa**
e um plano de correção passo a passo. A primeira resposta é persistida no PostgreSQL e volta a
ser exibida sem nova chamada ou gasto de tokens. Somente administradores podem solicitar uma
nova versão; a anterior permanece no histórico e uma falha nunca apaga a resposta válida.
Visualizadores podem consultar as respostas salvas, mas não gerar IA nem alterar dados.

Os provedores Anthropic e OpenAI já são intercambiáveis. Para usar o Claude Haiku 4.5, defina
`AI_PROVIDER=anthropic` e preencha somente `ANTHROPIC_API_KEY` no `.env`. Para trocar depois,
use `AI_PROVIDER=openai` e `OPENAI_API_KEY`. As chaves ficam apenas no backend, nunca usam o
prefixo `NEXT_PUBLIC_` e não devem ser commitadas. Consulte [`docs/ai.md`](docs/ai.md) para a
configuração completa.

Sem uma chave ativa, a aplicação continua funcionando e mostra um plano-base identificado como
tal. A chamada só ocorre por ação explícita, usa saída estruturada e limita o texto técnico.
Um filtro remove padrões de IPs, hostnames, URLs e e-mails antes do envio, mas não garante
anonimização completa de evidências em texto livre. Use somente dados autorizados pela
organização. Na integração OpenAI, a requisição solicita que a resposta não seja armazenada.
Tokens, custo estimado, modelo, provedor, versão do prompt e data ficam registrados localmente.

O controle de acesso possui quatro perfis: **Administrador**, **Gestor**, **Analista** e
**Visualizador**. A interface esconde ações não permitidas e a API valida novamente cada
operação, evitando que uma restrição seja burlada por uma chamada manual. A matriz completa,
as proteções contra perda do último administrador e a recomendação de autenticação para
produção estão em [`docs/access-control.md`](docs/access-control.md).

O arquivo enviado é temporário e removido após o processamento. Não adicione
exportações reais ao Git, pois elas contêm um mapa sensível do ambiente.

O upload usa um registro de adaptadores: hoje o Nessus está ativo e novos scanners podem ser
adicionados sem reescrever o fluxo de importação. Consulte
[`docs/scanner-adapters.md`](docs/scanner-adapters.md). A configuração segura e o ciclo do
conector Jira estão em [`docs/ticketing.md`](docs/ticketing.md).

O Docker é a forma oficial de execução para manter o ambiente do hackathon e do projeto acadêmico reproduzível.

## Diagnóstico de instalação

Se o login informar falha de conexão, execute na raiz do projeto (Node.js 24 ou superior):

```bash
npm run doctor
```

Não é necessário instalar pacotes npm para esse comando. Ele confere `.env`, Docker,
serviços, prontidão da API e autorização CORS, sem alterar configurações ou imprimir segredos.
O clone pelo Git não inclui `.env`, usuários, dados do PostgreSQL ou scans reais.
Veja [o guia de diagnóstico](docs/local-diagnostics.md), inclusive para Windows.

Depois de trocar a chave no `.env`, carregue-a novamente com:

```bash
docker compose up -d --no-deps --force-recreate api
```

Não basta editar `.env.example` ou atualizar a página. Erros de configuração, chave, saldo,
conexão e limite de saída agora recebem orientações distintas. Uma tentativa pode ser cobrada
pelo provedor mesmo quando não resulta em análise salva; não há repetição automática.

## Administração da IA

Administradores encontram o painel no menu **Administração da IA** (`/admin/ai`). Ele mostra
configuração sem segredos, análises/tokens/custo estimado de 7/30/90 dias, consumo por modelo
e falhas novas com orientação. A consulta não gera conteúdo nem consome tokens.
O custo exibido cobre apenas análises salvas, incluindo versões antigas; tentativas com custo
desconhecido ficam separadas. Não é uma fatura, consulta de saldo ou limite de orçamento.
Veja [as regras e limitações do monitor](docs/ai.md#painel-administrativo-local).

## Backup do banco

Com Docker aberto, na pasta deste projeto, execute `npm run backup` para criar uma
cópia local em `backups/`. O comando preserva o banco em uso, não copia `.env` e não
sobrescreve backups anteriores. Os arquivos contêm dados sensíveis e **não são
criptografados**: ficam fora do Git, mas exigem armazenamento protegido.

`npm run backup:verify -- "PASTA_DO_BACKUP"` confere a integridade.
`npm run backup:restore -- "PASTA_DO_BACKUP" --trusted` recupera um backup confiável
em **outro banco isolado**, sem substituir o atual ou mudar a aplicação automaticamente.
Leia [o guia de backup e recuperação](docs/backups.md) antes de restaurar.

## Exclusão de scans

Na página **Scans**, administradores podem usar **Excluir** na coluna **Ações**.
A confirmação identifica o scan e avisa que a remoção é definitiva na aplicação.
Scans em processamento não podem ser excluídos. Nada é removido do Nessus.

O scan e suas observações saem dos indicadores; se ele era o mais recente, um scan
anterior pode voltar a ser a referência. O ciclo de correções/reaberturas e o relatório
mensal são recalculados a partir dos scans restantes. Excluir não equivale a corrigir
uma vulnerabilidade. Registros operacionais, análises de IA, tickets e ativos
compartilhados são preservados, sem chamadas a provedores. A operação é auditada.
Guarde o `.nessus` original caso precise reimportar: não há botão de desfazer.

Veja [os detalhes e testes da exclusão](docs/scan-deletion.md).

## Testes de navegador

O ambiente E2E usa dados sintéticos, banco temporário separado e IA/Jira desativados.
Não utiliza o `.env` local nem os volumes da aplicação normal.

```bash
npm ci
npx playwright install chromium
npm run test:e2e:up
npm run test:e2e
npm run test:e2e:stop
```

A API de teste usa a porta 8001 e o frontend de teste, 3001. Não reutilize essas portas
para outros serviços durante a execução. O banco temporário perde os dados de teste
ao ser parado; os dados da aplicação normal não são afetados. Consulte
[o protocolo de testes](docs/browser-tests.md) para os cenários, limites e relatórios.

## Revisão das dependências

A revisão de 09/11/2026 atualizou Next.js, PyJWT e ferramentas auxiliares. O relatório
registra os testes executados, as auditorias sem alertas nas dependências de produção
verificadas e os alertas moderados ainda presentes nas ferramentas de desenvolvimento.
Consulte [a revisão de segurança e suas limitações](docs/security-review.md).
O código público não deve conter `.env`, backups ou scans reais. Um repositório público
não equivale a uma aplicação pronta para ser exposta na internet.
