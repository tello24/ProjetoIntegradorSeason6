# Exclusão de scans

## Contrato e permissões

- `GET /api/v1/scans` informa `can_delete` para a interface.
- `DELETE /api/v1/scans/{id}` exige sessão válida e perfil **administrador**.
- A busca sempre inclui o cliente da sessão. IDs inexistentes ou de outro cliente
  respondem `404`, sem revelar o nome do scan. Perfis sem permissão recebem `403`.
- Apenas estados `concluido` e `falhou` podem ser removidos; os demais respondem `409`.
- A interface exige confirmação, impede cliques repetidos e mantém a linha em caso de erro.
- Não há exclusão em lote nem exclusão automática por idade.

## Efeito nos dados

Uma única transação remove o scan e, pelas chaves estrangeiras existentes, seus
achados, observações de ativos e serviços. Outros scans, hosts compartilhados e o
catálogo de plugins não são apagados. O registro da importação é mantido, mas perde
o vínculo com o scan removido. Seus contadores descrevem a importação original.

O histórico restante do cliente é reprocessado na ordem das importações, respeitando
o escopo de cada scan. Alterações manuais de etapa são reaplicadas em sua ordem
original, somente enquanto há observação e o achado não está resolvido por scan.
Responsáveis, prazos, anotações, análises pagas e vínculos de tickets não são apagados.
Sem observações remanescentes, o acompanhamento fica sem vínculo a um achado e não
entra na fila, no dashboard ou no relatório; permanece disponível se a mesma identidade
de vulnerabilidade for observada novamente. Isso não é uma ferramenta de apagamento
integral de dados pessoais.

Eventos automáticos anteriores são preservados como `workflow.superseded_auto_*`,
identificados pelo scan cuja exclusão exigiu o recálculo. Os eventos válidos são
reconstruídos nas datas dos scans, não na data da exclusão. O relatório mensal usa
os eventos válidos; o histórico operacional oculta os substituídos, que continuam
na tabela de auditoria. Um evento `scan.deleted` registra autor, ID, nome e contagens.

Importação e exclusão usam o mesmo bloqueio transacional por cliente para evitar
reconstruções concorrentes. Não há chamadas à IA ou ao Jira. Uma falha antes do
commit reverte a operação inteira. Não é necessário alterar o esquema do banco.

## Validação

Os testes usam exclusivamente dados sintéticos em banco isolado:

- permissão administrativa, ausência de sessão e consulta restrita por cliente;
- rejeição de scan em processamento ou já removido;
- exclusão intermediária desfazendo falsas correções/reaberturas;
- exclusão do mais recente retornando à observação anterior;
- exclusão do último scan sem deixar indicadores ou backlog fantasma;
- preservação de responsáveis, notas e análises de IA já salvas;
- reimportação do mesmo arquivo após exclusão;
- confirmação cancelada sem requisição, erro mantendo a linha e sucesso persistindo.

O recálculo percorre o histórico do cliente. Para volumes muito maiores que os do PI,
avaliar processamento em segundo plano e limites operacionais antes de produção.
