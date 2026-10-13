# Backlog de evolução

Este documento registra as melhorias aprovadas, seu desenho e o estado de cada entrega.
Itens marcados como planejados não devem ser implementados sem uma nova autorização.

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
