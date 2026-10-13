# Contexto de negócio dos ativos

O contexto de negócio complementa o inventário técnico do scanner com informações mantidas
pela equipe: ambiente, criticidade, responsável, equipe, serviço, unidade, exposição à
internet, janela de manutenção, tags e observações.

## Separação do risco técnico

A criticidade de negócio não altera o WVM Score. O score continua técnico, reproduzível e
baseado nos sinais da vulnerabilidade. A interface apresenta as duas dimensões separadamente
para que a equipe possa decidir a ordem de tratamento sem esconder a origem de cada avaliação.

## Autorização e isolamento

- Todos os perfis autenticados do cliente podem consultar o contexto.
- Administradores e gestores podem alterá-lo.
- O responsável escolhido precisa ser um usuário ativo do mesmo cliente.
- A API obtém o cliente da sessão; o navegador não envia nem escolhe `cliente_id`.
- O vínculo usa uma chave estrangeira composta entre cliente e ativo para impedir associação
  cruzada entre ambientes.

## Auditoria

Cada alteração efetiva gera um evento `asset.business_context_updated`, contendo autor, ativo,
campos modificados e estados anterior e novo. O envio repetido dos mesmos dados não cria um
novo evento nem muda a data de atualização.

## Indicadores

O inventário destaca ativos críticos com vulnerabilidades, ativos de produção sem scan
credenciado e ativos sem responsável. Ambiente e criticidade também podem ser usados como
filtros, enquanto responsável, equipe e serviço participam da pesquisa textual.

Em uma integração futura com CMDB, os mesmos campos poderão ser sincronizados mantendo as
regras de isolamento e a trilha de auditoria.
