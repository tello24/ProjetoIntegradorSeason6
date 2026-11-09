# Backup e recuperação local

Esta entrega protege o banco PostgreSQL 17 da versão da faculdade. É uma ferramenta
de terminal para o operador local, não um botão exposto aos usuários da aplicação.
Requer Docker Desktop em execução e Node.js 24+, mas não requer instalar ferramentas
PostgreSQL no computador nem pacotes npm adicionais.

## Criar uma cópia

Na pasta principal do projeto:

```bash
npm run backup
```

O comando usa o serviço `database` da configuração Docker Compose dessa pasta.
Confira que está na versão da faculdade e no contexto Docker correto. O banco deve
estar em execução. Não é necessário parar a aplicação. O `pg_dump` produz um snapshot
consistente mesmo com outras conexões usando o banco.

Uma pasta nova e exclusiva é criada em `backups/wvm-DATA-IDENTIFICADOR/`, contendo:

- `database.dump`: arquivo PostgreSQL no formato custom, comprimido;
- `manifest.json`: formato, data, tamanho, versão do PostgreSQL e SHA-256.

Uma falha não é anunciada como sucesso. Arquivos incompletos ficam na pasta indicada
para diagnóstico e não têm um manifesto válido. Não sobrescrevemos cópias anteriores
e não removemos backups automaticamente. Verifique espaço disponível regularmente.

Para escolher outra pasta local protegida:

```bash
npm run backup -- --output "/caminho/protegido/backups-wvm"
```

## Conferir integridade

Use a pasta exata mostrada ao criar o backup:

```bash
npm run backup:verify -- "backups/wvm-DATA-IDENTIFICADOR"
```

A conferência é local e não precisa do Docker: verifica manifesto, formato, tamanho
e checksum. **Checksum não comprova a origem do arquivo nem substitui uma restauração.**
Alguém que altere o dump e o manifesto pode recalcular o hash. Rejeitamos arquivos
corrompidos, versões incompatíveis e links simbólicos nos arquivos do backup.

## Recuperar em um banco separado

Somente para um backup próprio, de origem confiável:

```bash
npm run backup:restore -- "backups/wvm-DATA-IDENTIFICADOR" --trusted
```

`--trusted` confirma que você confia na origem: restaurar um dump executa SQL contido
nele. Não use backups recebidos de desconhecidos. O script:

1. Confere a integridade antes de criar recursos Docker.
2. Cria um contêiner PostgreSQL 17 e um volume novos, com identificadores aleatórios.
3. Não publica portas, não conecta à rede externa e não monta pastas do computador.
4. Restaura em uma transação; não usa `--clean` nem substitui bancos existentes.
5. Verifica tabelas essenciais e apresenta contagens, não o conteúdo dos registros.

Os nomes `wvm-restore-...` e `wvm-restore-...-data` são mostrados ao final. A cópia
recuperada fica preservada no volume local. Em caso de falha, o novo contêiner é parado
quando possível e os recursos são mantidos para diagnóstico. O banco original não é
apagado ou reconfigurado, e nenhuma chamada à IA ou ao Jira é feita.

**A aplicação NÃO passa a usar a cópia automaticamente.** Este é o primeiro estágio
da recuperação: uma cópia separada para inspeção e validação. A troca do banco ativo
exige uma janela planejada e revisão das configurações com o responsável técnico.
Não edite `DATABASE_URL`, apague volumes ou copie comandos de remoção como tentativa
genérica de ativar a recuperação. Em development, o bootstrap também pode atualizar
a senha administrativa ao iniciar a API; revise isso antes de uma troca de banco.

## O que entra e o que não entra

O backup inclui tabelas, índices, views e sequências do banco, com scans importados,
observações, usuários e hashes de senhas, permissões, contexto dos ativos, planos
operacionais, histórico, análises de IA salvas e vínculos dos tickets.

Não inclui:

- código, imagens Docker ou versões não commitadas do projeto;
- `.env`, chaves de provedores, segredo de sessão ou senhas de conexão do Compose;
- arquivos originais `.nessus` fora do banco (a aplicação descarta uploads temporários);
- dados externos do Nessus/Jira, configurações e créditos dos provedores;
- usuários globais/roles do cluster PostgreSQL ou outros bancos.

Mantenha código/versão, configurações e arquivos originais em armazenamento seguro
separado. Na recuperação isolada, os objetos pertencem ao usuário local de recuperação;
permissões globais de produção precisam de configuração explícita em uma implantação.

## Proteção e limites

- **Não há criptografia do arquivo.** Compressão e checksum não são criptografia.
- Pastas novas usam `0700` e arquivos `0600` em macOS/Linux. No Windows, proteja a pasta
  pelas permissões da conta. Não presumimos que permissões POSIX protegem arquivos no Windows.
- `backups/`, `*.dump`, `*.dump.partial` e `*.backup` ficam fora do Git e do build Docker.
  Isso não protege cópias renomeadas, pastas fora do padrão ou arquivos já rastreados.
- Dados sensíveis e hashes de senhas continuam presentes. Não envie esses arquivos ao
  GitHub, a chats ou a terceiros. Use disco/armazenamento criptografado com acesso restrito.
- Uma cópia apenas no mesmo computador não protege contra perda do equipamento.
  Uma segunda cópia protegida em outro local, retenção e agendamento exigem definição
  da equipe; não foram ativados nesta entrega.
- O fluxo é específico de PostgreSQL 17 e precisa de espaço para o backup e o banco
  recuperado. O teste estrutural não certifica todas as funcionalidades da aplicação.

## Testes

```bash
npm run test:backup
```

Valida integridade, corrupção, permissões, arquivos parciais, argumentos, confirmação
de confiança, recursos isolados, colisões de nomes e preservação em falhas, sem Docker.

O teste real usa dois bancos temporários exclusivos com fixtures fictícias. Não usa
`.env`, API keys, volumes da aplicação ou provedores externos. Com Docker disponível:

```bash
# macOS/Linux
RUN_BACKUP_INTEGRATION=1 npm run test:backup:integration
```

No PowerShell:

```powershell
$env:RUN_BACKUP_INTEGRATION = "1"
npm.cmd run test:backup:integration
Remove-Item Env:RUN_BACKUP_INTEGRATION
```

Ele compara registros e sequências entre origem e recuperação e remove somente seus
próprios contêineres, volume de recuperação e arquivos temporários. Um job separado
da CI executa esse teste quando as mudanças forem publicadas; não envia backups como
artefatos do GitHub.

Referências oficiais: [pg_dump](https://www.postgresql.org/docs/17/app-pgdump.html)
e [pg_restore](https://www.postgresql.org/docs/17/app-pgrestore.html).
