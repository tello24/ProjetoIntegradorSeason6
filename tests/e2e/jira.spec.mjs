import { expect, test } from "@playwright/test";

const api = "http://localhost:8001/api/v1";
async function login(page) {
  await page.goto("/login");
  await page.getByLabel("E-mail corporativo").fill("admin-e2e@example.com");
  await page.getByLabel("Senha", { exact: true }).fill("e2e-only-local-password");
  await page.getByRole("button", { name: "Entrar na plataforma" }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
}

test("Jira é cadastrado pela empresa sem expor token nem conectar automaticamente", async ({ page }) => {
  const errors = [], writes = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("request", request => { if (request.method() === "POST" && request.url().includes("/admin/jira/")) writes.push(request.url()); });
  await login(page);
  await page.getByRole("navigation").getByRole("link", { name: "Integração Jira", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Integração Jira", exact: true })).toBeVisible();
  await expect(page.getByText(/As conexões externas com o Jira estão desativadas/)).toBeVisible();
  await page.getByLabel("Endereço Jira Cloud").fill("https://synthetic.atlassian.net");
  await page.getByLabel("E-mail da conta de integração").fill("jira-synthetic@example.com");
  await page.getByLabel(/Token da API/).fill("synthetic-test-token-not-real");
  await page.getByLabel("Chave do projeto").fill("SEC");
  await page.getByRole("button", { name: "Salvar configuração" }).click();
  await expect(page.getByRole("status")).toContainText("Configuração salva");
  await expect(page.getByLabel(/Token da API/)).toHaveValue("");
  await expect(page.getByRole("button", { name: "Testar conexão" })).toBeDisabled();
  const saved = await page.request.get(`${api}/admin/jira`);
  expect((await saved.json()).has_token).toBe(true);
  expect(await saved.text()).not.toContain("synthetic-test-token-not-real");
  await page.reload();
  await expect(page.getByLabel(/Token da API/)).toHaveValue("");
  await expect(page.getByLabel("Endereço Jira Cloud")).toHaveValue("https://synthetic.atlassian.net");
  await page.getByRole("button", { name: "Usar tema escuro", exact: true }).click();
  await page.screenshot({ path: "test-results/jira-admin-dark.png", fullPage: true });
  await page.getByRole("button", { name: "Usar tema claro", exact: true }).click();
  await page.screenshot({ path: "test-results/jira-admin-light.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: "test-results/jira-admin-mobile.png", fullPage: true });
  expect(writes).toEqual([]);
  expect(errors).toEqual([]);
});

test("prévia exige confirmação e falha ambígua não oferece criação duplicada", async ({ page }) => {
  await login(page);
  const name = `Jira synthetic ${Date.now()}`;
  const timestamp = Math.floor(Date.now() / 1000);
  const xml = `<NessusClientData_v2><Report name="${name}"><ReportHost name="192.0.2.80"><HostProperties><tag name="host-ip">192.0.2.80</tag><tag name="HOST_START_TIMESTAMP">${timestamp - 60}</tag><tag name="HOST_END_TIMESTAMP">${timestamp}</tag></HostProperties><ReportItem port="443" protocol="tcp" severity="3" pluginID="900992" pluginName="${name}" pluginFamily="General"><description>Synthetic</description><solution>Synthetic</solution></ReportItem></ReportHost></Report></NessusClientData_v2>`;
  const imported = await page.request.post(`${api}/scans/import`, { multipart: { file: { name: "jira.nessus", mimeType: "application/xml", buffer: Buffer.from(xml) } } });
  expect(imported.status()).toBe(202);
  const importId = (await imported.json()).id;
  await expect.poll(async () => (await (await page.request.get(`${api}/scans/imports/${importId}`)).json()).status).toBe("concluido");
  const list = await (await page.request.get(`${api}/vulnerabilities?search=${encodeURIComponent(name)}`)).json();
  const id = list.items.find(item => item.title === name).id;
  await page.goto(`/vulnerabilities/${id}`);
  const state = { provider: "jira", enabled: true, can_create: true, can_reconcile: false, ticket: null };
  const preview = { summary: "Ticket sintético", description_lines: ["Responsável: Analista de exemplo", "Correção já salva"], fingerprint: "a".repeat(64), site_url: "https://synthetic.atlassian.net", project_key: "SEC", issue_type: "Task" };
  let creates = 0, reconciles = 0;
  await page.route(`${api}/vulnerabilities/${id}/ticket**`, async route => {
    const req = route.request();
    if (req.url().endsWith("/preview")) return route.fulfill({ json: preview });
    if (req.method() === "POST" && req.url().endsWith("/reconcile")) {
      reconciles++; state.ticket = { ...state.ticket, status: "created", external_key: "SEC-42", external_url: "https://synthetic.atlassian.net/browse/SEC-42", error: null }; state.can_reconcile = false;
      return route.fulfill({ json: state });
    }
    if (req.method() === "POST") {
      creates++; expect(req.postDataJSON()).toEqual({ preview_fingerprint: preview.fingerprint });
      state.can_create = false; state.can_reconcile = true;
      state.ticket = { id: "synthetic", status: "uncertain", error: "Resultado não confirmado." };
      return route.fulfill({ status: 502, json: { detail: "Resultado não confirmado." } });
    }
    return route.fulfill({ json: state });
  });
  await page.getByRole("button", { name: "Atualizar vínculo" }).click();
  await page.getByRole("button", { name: "Revisar ticket no Jira" }).click();
  const panel = page.getByRole("region", { name: "Prévia do ticket" });
  await expect(panel).toContainText("Ticket sintético");
  expect(creates).toBe(0);
  await panel.getByRole("button", { name: "Cancelar", exact: true }).click();
  expect(creates).toBe(0);
  await page.getByRole("button", { name: "Revisar ticket no Jira" }).click();
  await page.getByRole("button", { name: "Confirmar envio ao Jira" }).click();
  await expect(page.getByText(/O Jira pode ter criado o ticket/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Revisar ticket no Jira" })).toHaveCount(0);
  await page.getByRole("button", { name: "Verificar ticket no Jira" }).click();
  await expect(page.getByRole("link", { name: "Abrir no Jira ↗" })).toHaveAttribute("href", "https://synthetic.atlassian.net/browse/SEC-42");
  expect(creates).toBe(1); expect(reconciles).toBe(1);
});
