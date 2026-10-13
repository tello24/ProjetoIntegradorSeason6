# WVM Score 1.0

O WVM Score organiza os achados técnicos em uma fila de atuação transparente. Ele não
substitui uma análise de risco de negócio e não esconde multiplicadores proprietários.

## Composição atual

| Sinal | Peso máximo |
| --- | ---: |
| CVSS mais recente disponível | 55 |
| Probabilidade EPSS | 25 |
| Exploit disponível no scanner | 10 |
| Tenable VPR | 10 |

Quando o arquivo não informa CVSS, o sistema usa a severidade do scanner como fallback.
EPSS e VPR ausentes contribuem com zero e aparecem como informação ausente na explicação.

## Faixas de decisão

- `80–100`: agir agora;
- `60–79`: priorizar;
- `35–59`: planejar;
- `0–34`: monitorar.

## Pontuação consolidada do dashboard

O cartão “Pontuação de risco” é uma visão do ambiente, diferente do WVM Score individual. Ele
usa o scan mais recente de cada escopo, atribui 10 pontos por crítica, 5 por alta, 2 por média
e 1 por baixa, divide a soma pela quantidade de ativos e limita o resultado a 100.

As duas fórmulas permanecem estáveis. Qualquer alteração futura de pesos exige uma nova versão,
documentação e testes para manter as decisões auditáveis.
