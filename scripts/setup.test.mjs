import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parseEnv } from "node:util";
import { checkConfiguration } from "./doctor.mjs";
import { createLocalConfiguration, setupLocal } from "./setup.mjs";

const example = readFileSync(new URL("../.env.example", import.meta.url), "utf8");

test("creates unique coherent credentials without enabling paid integrations", () => {
  const first = parseEnv(createLocalConfiguration(example));
  const second = parseEnv(createLocalConfiguration(example));
  for (const key of ["APP_SECRET_KEY", "POSTGRES_PASSWORD", "BOOTSTRAP_ADMIN_PASSWORD"]) {
    assert.ok(first[key].length >= 32);
    assert.notEqual(first[key], second[key]);
  }
  assert.notEqual(first.POSTGRES_PASSWORD, first.BOOTSTRAP_ADMIN_PASSWORD);
  assert.equal(first.AI_PROVIDER, "disabled");
  assert.equal(first.TICKET_PROVIDER, "disabled");
  for (const key of ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "JIRA_API_TOKEN"]) assert.equal(first[key], "");
  assert.equal(checkConfiguration(first).filter((item) => item.status === "error").length, 0);
});

test("supports Windows line endings and rejects incomplete templates", () => {
  assert.equal(parseEnv(createLocalConfiguration(example.replaceAll("\n", "\r\n"))).AI_PROVIDER, "disabled");
  assert.throws(() => createLocalConfiguration("POSTGRES_USER=user\nPOSTGRES_DB=db\n"));
});

test("creates a local file once, restricts POSIX access and never overwrites it", (t) => {
  const cwd = mkdtempSync(join(tmpdir(), "wvm-setup-test-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  writeFileSync(join(cwd, ".env.example"), example);
  assert.deepEqual(setupLocal({ cwd }), { created: true });
  const file = join(cwd, ".env");
  if (process.platform !== "win32") assert.equal(statSync(file).mode & 0o777, 0o600);
  const before = readFileSync(file, "utf8");
  assert.deepEqual(setupLocal({ cwd }), { created: false });
  assert.equal(readFileSync(file, "utf8"), before);
});

test("preserves an existing configuration even when the example is unavailable", (t) => {
  const cwd = mkdtempSync(join(tmpdir(), "wvm-setup-test-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  writeFileSync(join(cwd, ".env"), "existing-test-configuration");
  assert.deepEqual(setupLocal({ cwd }), { created: false });
  assert.equal(readFileSync(join(cwd, ".env"), "utf8"), "existing-test-configuration");
});
