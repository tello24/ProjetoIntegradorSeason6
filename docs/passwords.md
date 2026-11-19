# Senhas e recuperação de acesso

Novos usuários criados em **Acessos** precisam trocar a senha inicial no primeiro login.
O servidor retorna 428 para os demais recursos até a troca. Visualizadores também podem
alterar a própria senha; isso não concede nenhuma permissão operacional adicional.
Contas anteriores à migration 011 não são forçadas a trocar, preservando acessos existentes.
O link **Alterar senha**, abaixo do perfil, permite trocar voluntariamente a senha atual.

Troca autenticada exige senha atual, nova senha diferente com 12–200 caracteres e confirmação
na interface. Após trocar ou recuperar, todas as sessões anteriores são invalidadas por versão
da conta, inclusive em outras empresas às quais ela pertença. É necessário entrar novamente.
Nenhuma senha é armazenada em texto puro; o hash continua usando Argon2.

## E-mail desativado por padrão

O botão **Esqueci minha senha** está disponível, mas sem configuração retorna uma orientação
clara de indisponibilidade. Não há link de recuperação exibido no navegador, logs ou resposta
da API. Não existe desvio por “modo desenvolvimento” para revelar o token.

Antes de habilitar, configurar no `.env` do servidor:

```env
PASSWORD_EMAIL_ENABLED=false
SMTP_HOST=
SMTP_PORT=465
SMTP_SECURITY=ssl
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=
```

Escolher `ssl` (usualmente porta 465) ou `starttls` (usualmente 587), conforme o serviço.
TLS com certificado verificado é obrigatório; não existe fallback para envio sem criptografia.
Usar credencial dedicada e remetente autorizado. `APP_PUBLIC_URL` deve ser a URL pública HTTPS
confiável da aplicação (HTTP localhost é aceito apenas em desenvolvimento). Nunca se usa o
cabeçalho Host enviado pelo solicitante para montar o link.

Depois de configurar e autorizar um teste real, definir `PASSWORD_EMAIL_ENABLED=true` e
recriar a API. Não comitar `.env`, senha SMTP, links de recuperação ou backups.

## Proteções e operação

- Resposta genérica idêntica para e-mails cadastrados e não cadastrados, com envio em segundo plano.
- Até 3 pedidos por e-mail/hora, 10 por IP/hora, 20 tentativas de redefinição por IP/hora
  e 10 tentativas de troca por conta/hora. Contadores persistem no banco; e-mail/IP são HMAC.
- Tokens aleatórios de 256 bits, validade de 20 minutos e armazenamento apenas do SHA-256.
- Uso único, com bloqueio transacional da conta. Alterar a senha invalida todos os links pendentes.
- O token fica no fragmento da URL e é removido do endereço ao abrir a tela, não indo no Referer.
  Se recarregar a página, reabra o link recebido no e-mail.
- Contas e vínculos inativos não recebem recuperação. O fluxo não ativa contas ou muda perfis.
- Falha SMTP invalida o link daquela tentativa e registra somente `password_email_delivery_failed`,
  sem endereço, token, conteúdo da mensagem ou detalhes de autenticação.
- E-mail de aviso após a alteração, quando o envio está configurado. Falha nesse aviso não desfaz
  uma troca concluída. O usuário deve tentar entrar com a senha nova se a resposta da troca se perder.
- O administrador cadastra um e-mail confiável no provisionamento; confirmação de endereço por
  convite e MFA ainda não estão implementados.

O envio em segundo plano não é uma fila durável: reiniciar a API pode perder um envio pendente;
o usuário pode solicitar outro link dentro dos limites. Em produção, evoluir para fila com
monitoramento e ajustar limites ao uso/proxy: o IP é o da conexão direta, não um X-Forwarded-For
arbitrário. As regras acima protegem estas novas rotas, não substituem controles de login/WAF.

Migrations: `011_password_recovery.sql`, aplicada pelo Compose. Testes usam contas fictícias,
PostgreSQL temporário e SMTP simulado/bloqueado. Referência de segurança:
[OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).
