import { expect, test } from "@playwright/test";

const api = "http://localhost:8001/api/v1";
const email = "admin-e2e@example.com";
const password = "e2e-only-local-password";

// No real scans or AI keys. Names and test-network addresses are deliberately synthetic.
function scan(name, plugin = "900001") {
  const timestamp = Math.floor(Date.now() / 1000);
  return Buffer.from(`<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2><Policy><policyName>${name}</policyName></Policy>
<Report name="${name}"><ReportHost name="192.0.2.10"><HostProperties>
<tag name="host-ip">192.0.2.10</tag><tag name="host-fqdn">wvm-e2e.example.com</tag>
<tag name="operating-system">Linux sintético</tag><tag name="Credentialed_Scan">true</tag>
<tag name="HOST_START_TIMESTAMP">${timestamp - 60}</tag>
<tag name="HOST_END_TIMESTAMP">${timestamp}</tag></HostProperties>
<ReportItem port="443" svc_name="https" protocol="tcp" severity="4"
 pluginID="${plugin}" pluginName="Achado sintético ${name}" pluginFamily="General">
<risk_factor>Critical</risk_factor><cvss3_base_score>9.8</cvss3_base_score>
<synopsis>Descrição exclusivamente para teste.</synopsis>
<description>Achado fictício para validar a interface.</description>
<solution>Aplicar a correção fictícia em ambiente de teste.</solution>
<plugin_output>Evidência sintética.</plugin_output>
</ReportItem></ReportHost></Report></NessusClientData_v2>`);
}

async function login(page, credentials = { email, password }) {
  await page.goto("/login");
  await page.getByLabel("E-mail corporativo").fill(credentials.email);
  await page.getByLabel("Senha", { exact: true }).fill(credentials.password);
  await page.getByRole("button", { name: "Entrar na plataforma" }).click();
}

test("painel da IA consulta dados sem gerar análises e permite recuperar erro", async ({ page }) => {
  const browserErrors = [];
  page.on("pageerror", (error) => browserErrors.push(error.message));
  expect((await page.request.get(`${api}/admin/ai/summary`)).status()).toBe(401);
  await page.goto("/admin/ai");
  await expect(page).toHaveURL(/\/login(?:\?|$)/);
  await login(page);
  await expect(page).toHaveURL(/\/dashboard$/);
  const generationRequests = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().includes("/remediation")) generationRequests.push(request.url());
  });
  await page.getByRole("navigation").getByRole("link", { name: "Administração da IA", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Administração da IA", exact: true })).toBeVisible();
  await expect(page.getByText("IA desativada", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Consumo local da IA" })).toContainText("Custo conhecido estimado");
  await expect(page.getByText(/A validade da chave, o saldo/)).toBeVisible();
  await page.getByLabel("Período do consumo").selectOption("7");
  await expect(page.getByRole("button", { name: "Atualizar dados" })).toBeEnabled();
  await page.getByRole("button", { name: "Atualizar dados" }).click();
  await expect(page.getByText("IA desativada", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Usar tema escuro", exact: true }).click();
  await page.screenshot({ path: "test-results/ai-admin-dark.png", fullPage: true });
  await page.getByRole("button", { name: "Usar tema claro", exact: true }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.screenshot({ path: "test-results/ai-admin-light.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("button", { name: "Atualizar dados" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: "test-results/ai-admin-mobile.png", fullPage: true });
  await page.route(`${api}/admin/ai/summary?*`, (route) => route.fulfill({ status: 503 }));
  await page.getByRole("button", { name: "Atualizar dados" }).click();
  await expect(page.locator(".page-content").getByRole("alert")).toContainText("A API não conseguiu carregar");
  await page.unroute(`${api}/admin/ai/summary?*`);
  await page.getByRole("button", { name: "Atualizar dados" }).click();
  await expect(page.getByText("IA desativada", { exact: true })).toBeVisible();
  expect(generationRequests).toEqual([]);
  expect(browserErrors).toEqual([]);
});

test("consumo por pessoa mostra ranking, detalhes, paginação e falhas sem gerar IA", async ({ page }) => {
  const errors = [];
  const generationRequests = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().includes("/remediation")) generationRequests.push(request.url());
  });
  await login(page);
  await expect(page).toHaveURL(/\/dashboard$/);
  const user = "00000000-0000-4000-8000-000000000001";
  let snapshot;
  await page.route(`${api}/admin/ai/summary?*`, async (route) => {
    const response = await route.fetch();
    const summary = await response.json();
    snapshot = summary.as_of;
    await route.fulfill({ json: { ...summary,
      usage: { analyses: 22, input_tokens: 6600, output_tokens: 3300, estimated_cost_usd: 0.033 },
      last_success_at: snapshot, failures: 1, failures_unknown_cost: 1, configuration_blocks: 0,
      models: [{ provider: "anthropic", model: "synthetic-model", analyses: 22,
        input_tokens: 6600, output_tokens: 3300, estimated_cost_usd: 0.033 }],
      recent_failures: [{ id: 1, occurred_at: snapshot, provider: "anthropic", error_code: "timeout",
        guidance: "Tentativa sintética interrompida. Confira a configuração antes de tentar novamente.", cost_status: "unknown" }],
      users: [
        { user_id: user, name: "Ana Exemplo", active: true, analyses: 22, vulnerabilities: 21,
          input_tokens: 6600, output_tokens: 3300, estimated_cost_usd: 0.033, failures_unknown_cost: 0, configuration_blocks: 0 },
        { user_id: null, name: "Autoria não registrada", active: false, analyses: 0, vulnerabilities: 0,
          input_tokens: 0, output_tokens: 0, estimated_cost_usd: 0, failures_unknown_cost: 1, configuration_blocks: 0 },
      ],
    } });
  });
  let failNext = false;
  await page.route(`${api}/admin/ai/users/*/vulnerabilities?*`, async (route) => {
    const url = new URL(route.request().url());
    expect(url.searchParams.get("as_of")).toBe(snapshot);
    if (failNext) { failNext = false; await route.fulfill({ status: 503 }); return; }
    const currentPage = Number(url.searchParams.get("page"));
    const missing = url.pathname.includes("unattributed");
    const items = Array.from({ length: missing ? 0 : currentPage === 1 ? 20 : 1 }, (_, i) => {
      const index = (currentPage - 1) * 20 + i;
      return { workflow_id: `synthetic-${index}`, finding_id: index === 0 ? 42 : null,
        title: `Vulnerabilidade sintética ${index + 1}`, plugin_id: 900000 + index,
        asset: "192.0.2.10", protocol: "tcp", port: 443, analyses: index === 0 ? 2 : 1,
        input_tokens: index === 0 ? 600 : 300, output_tokens: index === 0 ? 300 : 150,
        estimated_cost_usd: index === 0 ? 0.003 : 0.0015, last_generated_at: snapshot };
    });
    await route.fulfill({ json: { items, page: currentPage, page_size: 20, total: missing ? 0 : 21 } });
  });
  await page.goto("/admin/ai");
  const ranking = page.getByRole("table", { name: "Consumo por pessoa", exact: true });
  await expect(ranking.getByRole("row").nth(1)).toContainText("Ana Exemplo");
  await expect(ranking).toContainText("9.900");
  await expect(ranking).toContainText("0,033000");
  await expect(ranking).toContainText("tentativa(s) com custo desconhecido");
  await page.getByRole("button", { name: "Ver vulnerabilidades de Ana Exemplo" }).click();
  const details = page.getByRole("table", { name: "Vulnerabilidades de Ana Exemplo", exact: true });
  await expect(details.getByRole("link", { name: "Vulnerabilidade sintética 1", exact: true })).toHaveAttribute("href", "/vulnerabilities/42");
  await expect(details).toContainText("histórico de consumo preservado");
  await expect(page.getByRole("button", { name: "Página anterior", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Usar tema escuro", exact: true }).click();
  await page.screenshot({ path: "test-results/ai-people-dark.png", fullPage: true });
  await page.getByRole("button", { name: "Próxima página", exact: true }).click();
  await expect(details).toContainText("Vulnerabilidade sintética 21");
  await expect(page.getByRole("button", { name: "Próxima página", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Usar tema claro", exact: true }).click();
  await page.screenshot({ path: "test-results/ai-people-light.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: "test-results/ai-people-mobile.png", fullPage: true });
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.getByRole("button", { name: "Ver vulnerabilidades de Autoria não registrada" }).click();
  await expect(page.getByText("Nenhuma análise salva para esta pessoa neste período.")).toBeVisible();
  failNext = true;
  await page.getByRole("button", { name: "Ver vulnerabilidades de Ana Exemplo" }).click();
  await expect(page.locator("#ai-user-detail").getByRole("alert")).toContainText("Não foi possível consultar");
  await page.getByRole("button", { name: "Tentar consultar novamente" }).click();
  await expect(details).toBeVisible();
  await page.getByLabel("Período do consumo").selectOption("7");
  await expect(ranking).toBeVisible();
  await expect(page.locator("#ai-user-detail")).toHaveCount(0);
  expect(generationRequests).toEqual([]);
  expect(errors).toEqual([]);
});

test("visualizador consulta dados mas não gera IA, edita ou acessa a administração", async ({ page }) => {
  await login(page);
  await expect(page).toHaveURL(/\/dashboard$/);
  const viewer = { email: `ai-viewer-${Date.now()}@example.com`, password: "synthetic-viewer-password" };
  const created = await page.request.post(`${api}/access/users`, {
    headers: { Origin: "http://localhost:3001" },
    data: { name: "Visualizador sintético", email: viewer.email, temporary_password: viewer.password, role: "visualizador" },
  });
  expect(created.status()).toBe(201);
  const name = `VIEWER-E2E-${Date.now()}`;
  const imported = await page.request.post(`${api}/scans/import`, {
    multipart: { file: { name: "viewer-synthetic.nessus", mimeType: "application/xml", buffer: scan(name, "900003") } },
  });
  expect(imported.status()).toBe(202);
  const importId = (await imported.json()).id;
  await expect.poll(async () => {
    return (await (await page.request.get(`${api}/scans/imports/${importId}`)).json()).status;
  }).toBe("concluido");
  const findings = await (await page.request.get(`${api}/vulnerabilities?search=${name}`)).json();
  const findingId = findings.items[0].id;
  await page.getByRole("button", { name: "Sair da plataforma" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await login(page, viewer);
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByText("Visualizador", { exact: true })).toBeVisible();
  await expect(page.getByRole("navigation").getByRole("link", { name: "Administração da IA", exact: true })).toHaveCount(0);
  expect((await page.request.get(`${api}/admin/ai/summary`)).status()).toBe(403);
  await page.goto("/admin/ai");
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.goto(`/vulnerabilities/${findingId}`);
  await expect(page.getByRole("heading", { name: `Achado sintético ${name}`, exact: true })).toBeVisible();
  await expect(page.getByText(/Seu perfil permite apenas consultar análises salvas/)).toBeVisible();
  await expect(page.getByRole("button", { name: /GERAR ANÁLISE|GERAR NOVA VERSÃO|Salvar acompanhamento/ })).toHaveCount(0);
  await expect(page.getByRole("combobox", { name: "ETAPA", exact: true })).toBeDisabled();
  await expect(page.getByRole("combobox", { name: "RESPONSÁVEL", exact: true })).toBeDisabled();
  await expect(page.getByLabel("PRAZO", { exact: true })).toBeDisabled();
  await expect(page.getByRole("textbox", { name: "OBSERVAÇÃO", exact: true })).toBeDisabled();
  for (const suffix of ["remediation", "remediation/regenerate", "ticket"]) {
    expect((await page.request.post(`${api}/vulnerabilities/${findingId}/${suffix}`)).status()).toBe(403);
  }
  expect((await page.request.patch(`${api}/vulnerabilities/${findingId}/workflow`, { data: { status: "triage" } })).status()).toBe(403);
  await page.goto("/scan");
  await expect(page.getByRole("button", { name: "Importar scan", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Excluir scan/ })).toHaveCount(0);
  await page.getByRole("button", { name: "Sair da plataforma" }).click();
  await expect(page).toHaveURL(/\/login$/);
});

test.beforeAll(async ({ request }) => {
  const ready = await request.get(`${api}/health/ready`);
  expect(ready.ok(), "Inicie o ambiente isolado com npm run test:e2e:up").toBeTruthy();
  const auth = await request.post(`${api}/auth/login`, { data: { email, password } });
  expect(auth.ok()).toBeTruthy();
  // Refuse mutations if this port accidentally points to another installation.
  expect((await auth.json()).user.client_name).toBe("WVM E2E isolated");
});

test("rota protegida exige login e senha incorreta não vira erro de conexão", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login/);
  await login(page, { email, password: "incorrect-test-password" });
  await expect(page.locator("form").getByRole("alert")).toHaveText("E-mail ou senha inválidos.");
});

test("cookie inválido de outra instalação não provoca loop no login", async ({ page, context }) => {
  await context.addCookies([{ name: "ng_session", value: "invalid-old-session", domain: "localhost", path: "/" }]);
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("button", { name: "Entrar na plataforma" })).toBeVisible();
  await login(page);
  await expect(page).toHaveURL(/\/dashboard$/);
});

test("login explica falha de conexão e permite tentar novamente", async ({ page }) => {
  await page.route(`${api}/auth/login`, (route) => route.abort("connectionrefused"));
  await login(page);
  await expect(page.locator("form").getByRole("alert")).toContainText("Não foi possível conectar à API");
  await expect(page.locator("form").getByRole("alert")).toContainText("npm run doctor");
  await expect(page.getByRole("button", { name: "Entrar na plataforma" })).toBeEnabled();
  await page.unroute(`${api}/auth/login`);
  await page.getByRole("button", { name: "Entrar na plataforma" }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
});

test("login distingue erro interno de credencial inválida", async ({ page }) => {
  await page.route(`${api}/auth/login`, (route) => route.fulfill({ status: 503, contentType: "application/json", body: '{"detail":"unavailable"}' }));
  await login(page);
  await expect(page.locator("form").getByRole("alert")).toContainText("A API respondeu, mas não conseguiu concluir o login");
});

test("login lento termina com orientação e libera o botão", async ({ page }) => {
  // Hold the response until the real 15-second application timeout aborts it.
  await page.route(`${api}/auth/login`, () => {});
  await login(page);
  await expect(page.locator("form").getByRole("alert")).toContainText(
    "O login demorou mais que o esperado", { timeout: 20000 },
  );
  await expect(page.getByRole("button", { name: "Entrar na plataforma" })).toBeEnabled();
  await expect(page).toHaveURL(/\/login$/);
});

test("importação, dashboard, responsável, histórico e relatório funcionam no navegador", async ({ page }) => {
  const browserErrors = [];
  page.on("pageerror", (error) => browserErrors.push(error.message));
  const name = `E2E-${Date.now()}`;
  await login(page);
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.getByRole("navigation", { name: "Navegação principal" }).getByRole("link", { name: "Scans", exact: true }).click();
  await page.locator('input[type="file"]').setInputFiles({ name: "synthetic.nessus", mimeType: "application/xml", buffer: scan(name) });
  await expect(page.getByRole("status")).toContainText("1 ativos e 1 vulnerabilidades importados.");
  await expect(page.getByRole("table", { name: "Histórico de scans" })).toContainText(name);

  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Indicadores executivos" })).toContainText("Vulnerabilidades abertas");
  await page.goto("/vulnerabilities");
  await page.getByRole("searchbox", { name: "Pesquisar vulnerabilidades" }).fill(name);
  await page.getByRole("row", { name: `Abrir Achado sintético ${name} no ativo wvm-e2e.example.com` }).click();
  await expect(page.getByRole("heading", { name: `Achado sintético ${name}`, exact: true })).toBeVisible();
  await page.getByRole("combobox", { name: "ETAPA", exact: true }).selectOption("in_progress");
  await expect(page.getByRole("combobox", { name: "RESPONSÁVEL", exact: true })).toBeEnabled();
  await page.getByRole("combobox", { name: "RESPONSÁVEL", exact: true }).selectOption({ label: "Administrador E2E" });
  await page.getByLabel("PRAZO", { exact: true }).fill("2030-12-31");
  await page.getByRole("textbox", { name: "OBSERVAÇÃO", exact: true }).fill("Acompanhamento criado pelo teste de navegador.");
  await page.getByRole("button", { name: "Salvar acompanhamento" }).click();
  await expect(page.getByRole("status")).toContainText("Acompanhamento atualizado.");
  await page.reload();
  await expect(page.getByRole("combobox", { name: "ETAPA", exact: true })).toHaveValue("in_progress");
  await expect(page.getByRole("textbox", { name: "OBSERVAÇÃO", exact: true })).toHaveValue("Acompanhamento criado pelo teste de navegador.");
  await expect(page.getByRole("combobox", { name: "RESPONSÁVEL", exact: true }).locator("option:checked")).toHaveText("Administrador E2E");
  await expect(page.getByLabel("PRAZO", { exact: true })).toHaveValue("2030-12-31");

  // Deliberately uses the explicit fallback, never a paid provider.
  await page.getByRole("button", { name: /GERAR ANÁLISE UMA VEZ/ }).click();
  await expect(page.getByText("PLANO-BASE", { exact: true })).toBeVisible();
  await expect(page.locator(".ai-plan__warning")).toContainText("A IA está desativada");
  await expect(page.locator(".ai-plan__metadata")).not.toContainText("Sem consumo de tokens");
  const retry = page.getByRole("button", { name: "TENTAR GERAR ANÁLISE", exact: true });
  await expect(retry).toBeEnabled();
  let retryCalls = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/remediation")) retryCalls += 1;
  });
  page.once("dialog", (dialog) => dialog.dismiss());
  await retry.click();
  expect(retryCalls).toBe(0);
  page.once("dialog", (dialog) => dialog.accept());
  await retry.click();
  await expect(retry).toBeEnabled();
  expect(retryCalls).toBe(1);
  await page.goto("/reports/monthly");
  await expect(page.getByRole("heading", { name: "Comparativo mensal", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Detalhamento mensal", exact: true })).toBeVisible();
  await page.screenshot({ path: "test-results/monthly-report.png", fullPage: true });
  await page.getByRole("button", { name: "Sair da plataforma" }).click();
  await expect(page).toHaveURL(/\/login$/);
  expect(browserErrors, "Erros JavaScript ou de hidratação durante o fluxo").toEqual([]);
});

test("importação inválida informa o erro sem encerrar a sessão", async ({ page }) => {
  await login(page);
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.goto("/scan");
  await page.locator('input[type="file"]').setInputFiles({ name: "invalid.nessus", mimeType: "application/xml", buffer: Buffer.from("<not-nessus />") });
  await expect(page.getByRole("alert").filter({ hasText: /Nessus/i })).toBeVisible();
  await expect(page).toHaveURL(/\/scan$/);
  await expect(page.getByRole("button", { name: "Importar scan", exact: true })).toBeEnabled();
});

test("exclusão de scan pede confirmação, trata falhas e persiste", async ({ page }) => {
  const name = `DELETE-E2E-${Date.now()}`;
  await login(page);
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.goto("/scan");
  await page.locator('input[type="file"]').setInputFiles({
    name: "delete-synthetic.nessus", mimeType: "application/xml", buffer: scan(name, "900002"),
  });
  await expect(page.getByRole("status")).toContainText("1 ativos e 1 vulnerabilidades importados.");
  const row = page.getByRole("row").filter({ hasText: name });
  const remove = page.getByRole("button", { name: `Excluir scan ${name}`, exact: true });
  let deletes = 0;
  page.on("request", (request) => { if (request.method() === "DELETE") deletes += 1; });
  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toContain(name);
    expect(dialog.message()).toContain("não pode ser desfeita");
    await dialog.dismiss();
  });
  await remove.click();
  await expect(row).toBeVisible();
  expect(deletes).toBe(0);

  const deletionRoute = /\/api\/v1\/scans\/\d+$/;
  await page.route(deletionRoute, (route) => route.fulfill({
    status: 409, contentType: "application/json", body: '{"detail":"Aguarde o processamento."}',
  }));
  page.once("dialog", (dialog) => dialog.accept());
  await remove.click();
  await expect(page.getByRole("alert").filter({ hasText: "Aguarde o processamento." })).toBeVisible();
  await expect(row).toBeVisible();
  await expect(remove).toBeEnabled();
  await page.unroute(deletionRoute);

  page.once("dialog", (dialog) => dialog.accept());
  await remove.click();
  await expect(page.getByRole("status")).toContainText(`Scan “${name}” excluído.`);
  await expect(row).toHaveCount(0);
  expect(deletes).toBe(2);
  await page.reload();
  await expect(page.getByRole("row").filter({ hasText: name })).toHaveCount(0);
  await page.screenshot({ path: "test-results/scans-after-delete.png", fullPage: true });
});
