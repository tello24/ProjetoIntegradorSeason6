# WVM — Wolf Vulnerability Management

Aplicação interna em desenvolvimento.

## Estrutura

- `apps/web`: interface web em Next.js
- `apps/api`: API em FastAPI
- `database`: migrações e views do PostgreSQL
- `docs`: decisões técnicas do projeto
- `tests/fixtures`: amostras anonimizadas para testes

## Desenvolvimento local

1. Instale e abra o Docker Desktop.
2. Copie `.env.example` para `.env`.
3. Troque `APP_SECRET_KEY` e `BOOTSTRAP_ADMIN_PASSWORD` por valores locais.
4. Inicie os serviços com `docker compose up --build`.
5. Acesse a interface em `http://localhost:3000` e a documentação da API em `http://localhost:8000/docs`.

No primeiro início, o backend cria a organização e a conta local definidas no `.env`.
Use `BOOTSTRAP_ADMIN_EMAIL` e `BOOTSTRAP_ADMIN_PASSWORD` para entrar. Essa criação
automática só funciona quando `APP_ENV=development`.

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

Na página do achado, o usuário pode gerar uma explicação simples de **por que aquilo importa**
e um plano de correção passo a passo. A primeira resposta é persistida no PostgreSQL e volta a
ser exibida sem nova chamada ou gasto de tokens. Somente administradores podem solicitar uma
nova versão; a anterior permanece no histórico e uma falha nunca apaga a resposta válida.

Os provedores Anthropic e OpenAI já são intercambiáveis. Para usar o Claude Haiku 4.5, defina
`AI_PROVIDER=anthropic` e preencha somente `ANTHROPIC_API_KEY` no `.env`. Para trocar depois,
use `AI_PROVIDER=openai` e `OPENAI_API_KEY`. As chaves ficam apenas no backend, nunca usam o
prefixo `NEXT_PUBLIC_` e não devem ser commitadas. Consulte [`docs/ai.md`](docs/ai.md) para a
configuração completa.

Sem uma chave ativa, a aplicação continua funcionando e mostra um plano-base identificado como
tal. A chamada só ocorre por ação explícita, usa saída estruturada, não envia IP, hostname ou
evidência bruta do plugin e solicita à OpenAI que a resposta não seja armazenada pelo provedor.
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
