# Arquitetura inicial

O projeto segue um monorepositório simples, com responsabilidades isoladas:

```text
Navegador -> Next.js -> FastAPI -> PostgreSQL
                          |
                          +-> registro de adaptadores de scanners
                          +-> ciclo de vida por evidência de scan
                          +-> fluxo auditável de tratamento
                          +-> camada de IA (Anthropic ou OpenAI)
                          +-> conector de tickets (Jira)
```

## Princípios

1. O cliente autenticado é determinado no backend. A interface nunca escolhe livremente um `cliente_id`.
2. Arquivos `.nessus` são temporários, validados e removidos após o processamento.
3. Dados de produção e exportações reais nunca entram no repositório.
4. Métricas históricas preservam o estado do ativo no momento de cada scan.
5. O mesmo núcleo atende ao hackathon e ao PI; apenas dados, configuração e apresentação mudam.

## Fluxo funcional atual

- autenticação e rotas protegidas;
- dashboard com modos executivo e operacional, filtros globais e indicador de confiabilidade;
- histórico e importação de scans;
- Asset 360 com identidade técnica, cobertura, inventário de serviços, evidências e comparação
  histórica entre scans do mesmo escopo;
- contexto de negócio separado do WVM Score, com ownership, ambiente, criticidade e auditoria;
- pesquisa, filtros e detalhe de vulnerabilidades;
- acompanhamento por etapa, responsável e prazo, com histórico de auditoria;
- resolução e reabertura automáticas entre scans equivalentes, preservando o histórico;
- indicadores operacionais de remediação no dashboard;
- tema claro, escuro ou automático persistido no navegador;
- WVM Score e comparação entre scans do mesmo escopo;
- relatório mensal de entradas, correções, reaberturas e backlog, com exportação;
- explicação simples do impacto e plano de remediação assistidos por IA;
- cache persistente, versionamento, custos e auditoria das gerações de IA;
- fallback explícito para a recomendação do scanner quando não houver provedor disponível.
- criação idempotente de ticket Jira a partir da vulnerabilidade;
- descoberta dinâmica dos formatos de scanner registrados.

O Jira é o primeiro conector de tickets e o Nessus é o primeiro adaptador de scanner. Novos
provedores entram por esses contratos sem alterar as rotas principais. A IA nunca recebe
endereço, FQDN ou saída bruta do plugin e só é chamada
quando um usuário autorizado solicita a primeira análise ou um administrador confirma uma
regeneração. A interface sempre consulta o PostgreSQL antes do provedor. Trocar modelo ou
provedor não exclui as versões anteriores.

## Ciclo de vida dos achados

A identidade estável de uma vulnerabilidade combina cliente, ativo, plugin, protocolo e
porta. O escopo de comparação é derivado da política e do conjunto exato de endereços do
scan. Isso impede que um scan parcial ou de outro ambiente marque uma correção por engano.

- presente pela primeira vez: `open`;
- ausente no scan seguinte do mesmo escopo: `resolved`;
- presente de novo depois de resolvida: `reopened`;
- presente em scans consecutivos: mantém a etapa operacional existente.

Resoluções e reaberturas são eventos do sistema, gravados na auditoria com os scans que
forneceram a evidência. O usuário pode continuar a triagem de um item reaberto, mas não pode
marcar manualmente um achado como resolvido.
