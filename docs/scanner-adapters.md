# Adaptadores de scanners

Os dados de scanners passam por um contrato normalizado antes de chegar ao importador. O
registro informa nome, chave e extensões suportadas, enquanto cada adaptador converte seu
formato em ativos e achados padronizados.

O Nessus é o primeiro adaptador ativo. Para adicionar outro scanner:

1. implementar o protocolo `ScannerAdapter`;
2. converter severidade, identificador, evidências, CVSS, EPSS e referências para os modelos
   normalizados;
3. garantir que o identificador do plugin não colida com os demais fornecedores;
4. registrar o adaptador em `services/scanners/registry.py`;
5. adicionar amostras sintéticas e testes do parser, sem versionar dados reais de clientes.

O endpoint `GET /api/v1/scans/sources` permite que a interface descubra os formatos ativos.
Assim, a tela de upload acompanha o backend sem uma lista duplicada de extensões.

Comparações de ciclo de vida só acontecem entre scans com o mesmo escopo normalizado. A chave
histórica do Nessus foi preservada para que os scans já importados continuem comparáveis.
