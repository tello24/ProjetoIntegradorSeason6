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
