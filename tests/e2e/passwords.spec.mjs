import { expect, test } from "@playwright/test";

test("recuperação sem SMTP orienta sem fingir envio e link inválido não troca senha", async ({ page }) => {
  await page.goto("/login");
  await page.getByRole("link", { name: "Esqueci minha senha" }).click();
  await expect(page.getByRole("heading", { name: "Recuperar acesso" })).toBeVisible();
  await page.getByLabel("E-mail cadastrado").fill("no-mail@example.com");
  await page.getByRole("button", { name: "Enviar link de recuperação" }).click();
  await expect(page.locator(".form-error[role=alert]")).toContainText("ainda não está configurada");
  await page.goto("/reset-password");
  await expect(page.locator(".form-error[role=alert]")).toContainText("Link inválido");
  await expect(page.getByRole("button", { name: "Salvar nova senha" })).toBeDisabled();
  await page.goto(`/reset-password#token=${"a".repeat(43)}`);
  await expect(page).toHaveURL(/\/reset-password$/);
  await page.getByLabel("Nova senha", { exact: true }).fill("synthetic-password-one");
  await page.getByLabel("Confirmar nova senha").fill("synthetic-password-two");
  await page.getByRole("button", { name: "Salvar nova senha" }).click();
  await expect(page.locator(".form-error[role=alert]")).toContainText("precisam ser iguais");
  await page.getByLabel("Confirmar nova senha").fill("synthetic-password-one");
  await page.getByRole("button", { name: "Salvar nova senha" }).click();
  await expect(page.locator(".form-error[role=alert]")).toContainText("expirado ou já utilizado");
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: "test-results/password-reset-mobile.png", fullPage: true });
});
