# Controle de acesso

O WVM usa permissões por perfil e por ambiente do cliente. A função do usuário é consultada
no PostgreSQL em toda requisição autenticada; alterar ou desativar um acesso passa a valer sem
depender de um novo login.

## Matriz de permissões

| Ação | Administrador | Gestor | Analista | Visualizador |
| --- | --- | --- | --- | --- |
| Consultar dashboards, scans, ativos, achados e relatórios | Sim | Sim | Sim | Sim |
| Alterar o contexto de negócio dos ativos | Sim | Sim | Não | Não |
| Alterar etapa, responsável, prazo e observação | Sim | Sim | Sim | Não |
| Aplicar SLA e iniciar correção | Sim | Sim | Sim | Não |
| Aceitar formalmente um risco | Sim | Sim | Não | Não |
| Importar scans | Sim | Não | Sim | Não |
| Solicitar a primeira análise da IA | Sim | Não | Sim | Não |
| Gerar nova versão de uma análise da IA | Sim | Não | Não | Não |
| Criar ticket de vulnerabilidade | Sim | Sim | Sim | Não |
| Cadastrar, desativar ou alterar perfis | Sim | Não | Não | Não |

## Proteções aplicadas

- As permissões são conferidas pela API, não apenas pelos botões da interface.
- Usuários desativados deixam de autenticar e sessões existentes deixam de ser aceitas.
- Um administrador não pode rebaixar nem desativar o próprio acesso.
- O ambiente não pode ficar sem pelo menos um administrador ativo.
- Usuários inativos e visualizadores não aparecem na lista de responsáveis por correções.
- Alterações de acesso são registradas na auditoria com autor, alvo, estado anterior e novo.
- Alterações no contexto de negócio são isoladas por cliente e registradas na auditoria.

## Autenticação em produção

O cadastro atual usa e-mail e senha inicial para viabilizar o ambiente local, o hackathon e o
projeto acadêmico. Em produção, a recomendação é conectar o login ao provedor de identidade da
empresa por OIDC ou SAML, exigir MFA e manter esta mesma matriz de autorização dentro do WVM.
Enquanto o login local for usado, a senha inicial deve ser compartilhada por um canal seguro.
