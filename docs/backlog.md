# Backlog de evolução

Este documento registra as melhorias aprovadas, seu desenho e o estado de cada entrega.
Itens marcados como planejados não devem ser implementados sem uma nova autorização.

## Faculdade — estabilidade e instalação local

**Escopo:** repositório `tello24/ProjetoIntegradorSeason6`, partindo de `taskPI-frontend`.
O trabalho visual dessa branch é preservado; não se aplica automaticamente ao projeto da empresa.

### Primeira entrega

- Diagnóstico local somente leitura (`npm run doctor`), sem imprimir credenciais.
- Verificação de prontidão da API com banco e esquema básico; healthcheck no Compose.
- Login diferencia credenciais inválidas, indisponibilidade, erro interno e tempo excedido.
- Testes de navegador com API/PostgreSQL isolados, dados fictícios e IA/Jira desativados.
- Execução desses testes preparada na CI; publicação e execução no GitHub ainda dependem do push.
- Guias de instalação/diagnóstico e testes, incluindo cuidados para não apagar volumes reais.

### Critérios de aceite

1. O diagnóstico aponta configurações inconsistentes sem revelar os valores sensíveis.
2. Falhas do banco retornam estado genérico no endpoint de prontidão, sem SQL ou credenciais.
3. Login, importação, consulta e persistência do acompanhamento passam no navegador.
4. Dados, serviços e layout do projeto da empresa permanecem intactos.
5. Falhas da suíte geram evidências usando apenas informações sintéticas.

### Backup e recuperação local — implementado

- Backup PostgreSQL 17 em pasta exclusiva, arquivo custom e manifesto SHA-256.
- Verificação offline, permissões restritas em POSIX e exclusão dos arquivos do Git/build.
- Recuperação em contêiner e volume novos, sem rede externa ou portas publicadas.
- Banco ativo, `.env` e frontend preservados; sem IA/Jira e sem troca automática de banco.
- Testes unitários e recuperação real com dados fictícios, incluindo planos, IA e tickets.
- CI preparada para validar a recuperação; execução remota depende da publicação.
- Sem criptografia automática, retenção, agendamento ou cópia externa nesta etapa.

### Painel administrativo da IA — implementado

- Página `/admin/ai`, menu exclusivo do administrador e autorização na API.
- Configuração por lista permitida, sem chave, workspace ID ou outros segredos.
- Períodos móveis de 7/30/90 dias, todas as versões salvas e agrupamento por modelo.
- Custos históricos preservados; tentativas falhas com custo desconhecido separadas do total.
- Falhas novas registradas na auditoria com código seguro, sem prompt ou resposta bruta.
- Estados de carregamento, erro e ausência de registros; temas claro/escuro e responsividade.
- Não consulta saldo nem validade da chave, não chama provedores e não altera o `.env`.
- Limite de orçamento, bloqueio automático de gastos e conciliação com faturas não incluídos.

### Consumo de IA por conta e Visualizador somente leitura — implementado

- Ranking administrativo por custo estimado, nome, gerações, vulnerabilidades e tokens de entrada/saída.
- Detalhamento por vulnerabilidade em páginas de 20 itens, no mesmo período de 7/30/90 dias.
- Atribuição a quem pediu a geração, não ao responsável atual; histórico de versões preservado.
- Falhas com custo desconhecido, contas inativas e registros sem autoria tratados explicitamente.
- Consulta sem chamadas à IA e isolamento por cliente nas rotas de resumo/detalhamento.
- Bloqueio central de escrita para Visualizador; leitura de análises/histórico mantida.
- Testes de agregação com PostgreSQL isolado, autorização e navegação com dados fictícios.

### Dependências — revisão realizada em 09/11/2026

- Next.js e configuração do ESLint atualizados para 16.4.5, com lockfile atualizado.
- PyJWT atualizado para 2.15.1; pytest, certifi e pip também corrigidos nos ambientes pertinentes.
- Cinco testes adicionais de rejeição de sessões inválidas após a atualização do JWT.
- Auditorias sem alertas conhecidos nas dependências npm de produção, no ambiente Python
  local verificado e nas dependências Python da imagem Docker reconstruída.
- Oito pacotes de desenvolvimento ainda sinalizados pelo npm por uma mesma cadeia do
  minimatch; não foi aplicado downgrade forçado nem override de versão principal.
- Build, lint, 95 testes de API, 37 testes de ferramentas, dez testes de navegador e
  restauração PostgreSQL com dados fictícios aprovados localmente.
- CI preparada para bloquear alertas nas dependências npm de produção; execução remota
  depende da publicação. Relatório e limitações em [revisão de segurança](security-review.md).

**Pendências:** acompanhar a correção do minimatch nas ferramentas de desenvolvimento,
adotar travamento completo das dependências Python e repetir as auditorias nas atualizações.
O repositório pode ser público por decisão do grupo; isso não autoriza publicar dados reais,
credenciais ou expor o ambiente de desenvolvimento na internet.

## Asset 360 — ficha técnica completa do ativo

**Status:** implementado em setembro de 2026.

### Objetivo

Transformar o detalhe do ativo em um prontuário técnico que responda rapidamente o que é o
equipamento, como foi identificado, qual foi a qualidade do scan, quais serviços expõe, como
sua postura de segurança mudou e quais evidências sustentam essas informações.

### Organização da interface

1. **Visão geral:** identidade, sistema operacional, cobertura, postura de segurança e resumo
   das mudanças desde o scan anterior.
2. **Rede e serviços:** portas, protocolos, serviços, estado observado, achados relacionados e
   alterações entre scans.
3. **Vulnerabilidades:** achados ativos, severidades, WVM Score, CVEs, exploits, patches,
   situação de remediação e SLA.
4. **Histórico:** primeira e última observação, scans em que apareceu, evolução do risco,
   entradas, correções, reaberturas e mudanças na identidade técnica.
5. **Evidências técnicas:** metadados relevantes do scanner apresentados de forma estruturada,
   com conteúdo volumoso ou sensível recolhido por padrão.
6. **Contexto do negócio:** ambiente, criticidade, ownership, serviço, unidade, exposição,
   janela de manutenção, tags e observações operacionais.

### Informações previstas

- IP, hostname, FQDN, NetBIOS, MAC, UUID da BIOS e tipo de dispositivo;
- sistema operacional, versão, método e confiança da detecção e CPEs observados;
- primeiro e último avistamento, quantidade de scans e estado atual do ativo;
- scan credenciado, resultados autenticados e não autenticados, protocolo das verificações
  locais, política utilizada, início, término e duração do scan;
- portas abertas, protocolos, serviços e mudanças na superfície de rede;
- vulnerabilidades por severidade, maior WVM Score, CVEs, exploits, patches ausentes,
  vulnerabilidade mais antiga, reaberturas e itens com SLA vencido;
- comparação com o scan anterior: vulnerabilidades novas, corrigidas e reabertas, mudança de
  risco, portas adicionadas ou removidas e alterações de sistema ou cobertura.

### Dados disponíveis

O sistema persiste IP, FQDN, NetBIOS, MAC, UUID da BIOS, sistema operacional, tipo de sistema,
método e confiança da identificação, CPEs, cobertura credenciada, horários e política do scan,
resumo de patches, vulnerabilidades, inventário histórico de serviços e histórico de scans.

O importador usa uma lista explícita de propriedades permitidas. Informações de rota e outras
propriedades sensíveis ou volumosas do arquivo Nessus não são copiadas indiscriminadamente.

### Decisão de arquitetura

- Manter os campos comuns a qualquer scanner normalizados no banco.
- Guardar atributos específicos do scanner em metadados flexíveis e versionados, com uma lista
  explícita dos campos permitidos.
- Modelar portas e serviços como observações históricas separadas de vulnerabilidades. Um
  serviço informativo não deve virar um achado de segurança.
- Não persistir indiscriminadamente todas as propriedades ou saídas brutas do scanner; elas
  podem conter dados sensíveis, conexões internas e um volume muito alto.
- Preservar a origem, o scan e a data de cada informação para que a interface nunca apresente
  um dado antigo como se fosse atual.

### Entregas realizadas

1. Importação e banco ampliados com identidade, fingerprint e telemetria do scan.
2. Inventário histórico de portas e serviços separado dos achados.
3. API de detalhe com comparação somente entre scans equivalentes do mesmo escopo.
4. Seis abas: visão geral, contexto do negócio, rede e serviços, vulnerabilidades, histórico e
   evidências.
5. Alertas de cobertura, origem dos dados e testes automatizados com dados anonimizados.
6. Indicadores de ativos críticos vulneráveis, produção sem credencial e ownership pendente.
