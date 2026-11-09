# Revisão de dependências — 09/11/2026

## Escopo e resultado

Revisão da versão acadêmica (`tello24/ProjetoIntegradorSeason6`). Não é um pentest,
uma certificação de segurança nem uma avaliação das respostas de IA. Os resultados
são uma fotografia dos avisos conhecidos na data da consulta; podem mudar depois.

| Verificação | Antes | Depois |
| --- | --- | --- |
| `npm audit`, árvore completa | 13 pacotes sinalizados: 1 crítico, 4 altos e 8 moderados | 8 moderados, restritos à cadeia de desenvolvimento descrita abaixo |
| `npm audit --omit=dev` | Não registrado separadamente | 0 alertas |
| `pip-audit` sobre `.venv` local | 4 pacotes afetados | 0 alertas conhecidos nos 44 pacotes externos verificáveis |
| Pacotes Python instalados na nova imagem da API | Não registrado | 0 alertas nos 34 pacotes externos, incluindo pip |

O pacote da própria aplicação não está no PyPI e não foi analisado pelo `pip-audit`.
A ferramenta inicialmente emitiu 21 registros de avisos Python, alguns duplicados;
esse número **não** representa 21 falhas independentes. A tabela conta pacotes.
A auditoria do Docker foi feita a partir das versões efetivamente instaladas, não
apenas das versões permitidas pelo `pyproject.toml`.

## Alterações

- Next.js e `eslint-config-next`: 16.3.3 → 16.4.5.
- Atualização compatível das dependências transitivas `sharp`, `source-map-js`,
  `brace-expansion` e `zod`, registrada no `package-lock.json`.
- PyJWT: 2.13.0 → 2.15.1. A aplicação continua aceitando exclusivamente HS256;
  não foi relaxada a verificação de assinatura, emissor ou expiração.
- pytest: faixa `>=9.0.3,<10` (9.2.0 validado localmente).
- certifi: mínimo 2026.10.19 no grupo de desenvolvimento, utilizado pelo httpx
  dos testes (2026.10.23 instalado). Isso não altera o transporte da IA via urllib.
- pip: 26.3 no ambiente local de verificação, no build da API e na instalação da CI.
- Escopo padrão dos fixtures assíncronos explicitado como `function`.
- CI do frontend passa a executar `npm audit --omit=dev`. Nenhum alerta foi
  ocultado por `--ignore-vuln` ou por alteração artificial da severidade.

Referências dos mantenedores: [Next.js 16.4.5](https://github.com/vercel/next.js/releases/tag/v16.4.5),
[aviso do Next.js](https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw),
[PyJWT 2.15.1](https://github.com/jpadilla/pyjwt/releases/tag/2.15.1) e
[changelog do pytest](https://docs.pytest.org/en/stable/changelog.html#pytest-9-0-3-2026-04-07).

## Pendência de desenvolvimento: minimatch

Os oito pacotes moderados vêm da cadeia `eslint-config-next` → `typescript-eslint`
→ `@typescript-eslint/typescript-estree` → `minimatch@10.2.6`. Não são oito
vulnerabilidades independentes. O [aviso do mantenedor](https://github.com/isaacs/minimatch/security/advisories/GHSA-g3hv-75wg-m249)
descreve amplificação de padrões glob; a correção indicada é 11.0.1.

O upstream verificado ainda exige a faixa 10.x. A correção automática sugerida pelo npm
rebaixa `eslint-config-next` para 15.5.29. Não foi usado `npm audit fix --force` nem
forçada uma versão principal incompatível por override. Acompanhar o upstream e
revalidar o lint quando houver atualização compatível.

O Compose atual é de **desenvolvimento**: instala ferramentas de desenvolvimento e
executa `next dev`. Portanto, `npm audit --omit=dev` sem alertas **não** significa que
a imagem atual não contém os pacotes sinalizados ou que deva ser exposta na internet.
Não executar lint sobre código de origem desconhecida fora de um ambiente isolado.

## Validação local

- `npm run lint` e `npm run build`: aprovados com Next.js 16.4.5.
- `npm test`: 37 testes de setup, diagnóstico e backup aprovados; o comando de testes
  unitários próprio do frontend ainda não possui casos. A interface tem cobertura E2E.
- `ruff check apps/api`: aprovado.
- `pytest apps/api` com PostgreSQL 17 descartável e migrations: 95 testes aprovados.
  Inclui cinco novos casos de token expirado, emissor incorreto, expiração ausente,
  algoritmo diferente e ausência de assinatura. Nenhum caso de integração foi ignorado
  nessa execução completa; sem PostgreSQL, esse caso é pulado intencionalmente.
- Playwright/Chromium: dez cenários aprovados contra a API Docker reconstruída.
- Backup: criação, verificação e restauração de dados fictícios aprovadas; banco de
  origem do teste permaneceu inalterado.
- Nenhuma chamada paga à IA, nenhum ticket externo e nenhuma remoção de scan real.

Os testes unitários/integração da API usaram Python 3.14 local; a API Docker usada no
E2E foi construída com Python 3.13. Os checks remotos ainda precisam rodar no GitHub.
Existe aviso de depreciação do uso de httpx pelo TestClient no ambiente local; os
testes passam, mas essa migração deverá ser acompanhada separadamente.

## Como repetir e limitações

Após `npm ci`, executar `npm audit --omit=dev` e `npm audit` separadamente. A segunda
checagem continua retornando código de falha pelos oito alertas moderados conhecidos;
não ignorar automaticamente novos avisos.

Para Python, instalar `pip-audit` em ambiente separado e executar
`pip-audit --path CAMINHO_DO_SITE_PACKAGES_DA_API`. Auditar também as versões da
imagem efetivamente construída. Não instalar ferramentas de auditoria no container
principal em uso. Não usar `--fix` sem revisar as mudanças.

As dependências Python transitivas ainda não têm lockfile completo; novas instalações
podem resolver versões diferentes dentro das faixas permitidas. A imagem do sistema
operacional e suas bibliotecas nativas não foram cobertas por essas duas ferramentas.
Repetir auditoria, testes e revisão da imagem antes de qualquer implantação pública.

Antes de publicar código, conferir arquivos e diff staged. Nesta entrega não foram
incluídos `.env`, chaves privadas, exportações reais `.nessus` ou backups. A checagem
local de padrões de segredo não substitui uma análise de todo o histórico público.
