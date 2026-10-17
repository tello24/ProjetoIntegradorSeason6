# Testes de navegador do PI

## Escopo e isolamento

Os testes Playwright exercitam o frontend real da branch `taskPI-frontend`, a API FastAPI
real e um PostgreSQL separado. Não dependem de um layout antigo nem substituem o trabalho
visual da equipe. Seletores priorizam rótulos, funções e nomes acessíveis.

`compose.e2e.yml` é independente do Compose normal: usa valores de teste explícitos, sem
`env_file` ou referências às credenciais do `.env`; não monta volumes de dados existentes
e não publica a porta do banco. O projeto Docker chama-se `wvm-pi-e2e`.
A API fica em `127.0.0.1:8001`; o Playwright inicia o Next.js em `localhost:3001` e se
recusa a reutilizar um frontend que já esteja nessa porta. As credenciais incluídas são
fictícias e exclusivas desse ambiente. IA e Jira ficam desativados no backend.

Antes de alterar dados, a suíte valida o nome da organização de teste. Arquivos `.nessus`
são construídos em memória com endereço reservado para documentação e evidências fictícias.
Não há importação de dados empresariais, limpeza do banco real ou chamadas pagas.

## Executar

Pré-requisitos: Docker funcionando, Node.js 24+, dependências npm e Chromium do Playwright.

```bash
npm ci
npx playwright install chromium
npm run test:e2e:up
npm run test:e2e
npm run test:e2e:stop
```

No Linux, a instalação pode exigir `npx playwright install --with-deps chromium`.
Para uma nova rodada com banco limpo, pare apenas o ambiente E2E e inicie-o novamente.
O PostgreSQL usa armazenamento temporário em memória; parar o contêiner descarta os dados
sintéticos. Esses comandos não param a instalação normal nas portas 3000/8000.

## Cenários

1. Redirecionamento de rota protegida e rejeição de senha incorreta.
2. Mensagem de conexão indisponível, reabilitação do botão e recuperação do login.
3. Distinção entre falha interna da API e credencial inválida.
4. Tempo limite real de 15 segundos no login, mensagem explicativa e liberação do botão.
5. Login, importação pelo seletor de arquivo, dashboard, detalhe, atribuição de responsável,
   persistência do acompanhamento, plano-base sem IA paga, relatório mensal e logout.
6. Rejeição de XML inválido com preservação da sessão.

A suíte também observa erros JavaScript/hidratação durante o fluxo completo. O navegador
usa America/Sao_Paulo e o servidor UTC para revelar diferenças de renderização de datas.
Falhas guardam screenshot e trace em `test-results/`; `npm run test:e2e:report` abre
o relatório local. Esses diretórios são ignorados pelo Git. A CI retém os artefatos de
falha por sete dias; eles contêm apenas dados sintéticos.

## Limites

Essa suíte cobre Chromium desktop; não comprova acessibilidade completa, desempenho,
segurança, compatibilidade com todos os navegadores ou veracidade de respostas reais da IA.
O plano-base não é um teste de qualidade do modelo. Testes unitários existentes verificam
o contrato e os erros dos provedores com respostas simuladas. A execução da CI no GitHub
depende de publicar a branch e habilitar Actions no repositório.

## Diagnóstico e backend

`npm run test:doctor` valida os casos do diagnóstico local sem consultar seu Docker ou banco.
`pytest apps/api` inclui testes de prontidão com sessões simuladas. Os testes de integração
existentes exigem uma base dedicada e `RUN_DATABASE_TESTS=1`; nunca os aponte para produção.
