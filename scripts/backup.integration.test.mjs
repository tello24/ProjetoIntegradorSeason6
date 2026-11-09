import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { createBackup, databaseClient, docker, restoreBackup, verifyBackup } from "./backup.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const fixtureSQL = await readFile(new URL("./fixtures/backup.sql", import.meta.url), "utf8");
const snapshotSQL = `SELECT json_build_object(
    'scan', (SELECT nome FROM vm.scan WHERE id=1),
    'note', (SELECT observacao_atual FROM app.vulnerabilidade_tratamento LIMIT 1),
    'status', (SELECT status FROM app.vulnerabilidade_tratamento LIMIT 1),
    'assignee', (SELECT responsavel_id FROM app.vulnerabilidade_tratamento LIMIT 1),
    'password_hash', (SELECT senha_hash FROM app.usuario LIMIT 1),
    'ai', (SELECT conteudo FROM app.vulnerabilidade_analise_ia LIMIT 1),
    'cost', (SELECT custo_estimado_usd FROM app.vulnerabilidade_analise_ia LIMIT 1),
    'ticket', (SELECT chave_externa FROM app.vulnerabilidade_ticket LIMIT 1),
    'audit', (SELECT detalhes FROM app.evento_auditoria LIMIT 1)
)`;

async function query(container, sql) {
  return docker(["exec", "-i", container, "sh", "-c",
    'export PGPASSWORD="$POSTGRES_PASSWORD"; exec psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" -X -At -v ON_ERROR_STOP=1',
  ], { input: sql });
}

test("PostgreSQL 17: snapshot restores scans, users, workflow, AI, tickets and audit in isolation", {
  skip: process.env.RUN_BACKUP_INTEGRATION !== "1", timeout: 180_000,
}, async (t) => {
  const source = `wvm-backup-test-${randomBytes(8).toString("hex")}`;
  const outputDir = await mkdtemp(join(tmpdir(), "wvm-backup-integration-"));
  let recovery;
  let sourceCreated = false;
  t.after(async () => {
    // These identifiers are generated and owned exclusively by this test run.
    if (recovery) {
      await docker(["rm", "--force", recovery.container]).catch(() => {});
      await docker(["volume", "rm", recovery.volume]);
    }
    if (sourceCreated) await docker(["rm", "--force", source]);
    await rm(outputDir, { recursive: true, force: true });
  });
  await docker([
    "run", "--detach", "--name", source, "--network", "none", "--label", "wvm.backup.test=true",
    "--tmpfs", "/var/lib/postgresql/data",
    "--mount", `type=bind,source=${join(root, "database/migrations")},target=/docker-entrypoint-initdb.d,readonly`,
    "--env", "POSTGRES_DB=backup_test", "--env", "POSTGRES_USER=backup_test",
    "--env", "POSTGRES_PASSWORD", "postgres:17-alpine",
  ], { env: { POSTGRES_PASSWORD: randomBytes(24).toString("hex") } });
  sourceCreated = true;
  let ready = false;
  for (let i = 0; i < 60; i += 1) {
    try {
      await docker(["exec", source, "pg_isready", "-h", "127.0.0.1", "-U", "backup_test", "-d", "backup_test"]);
      ready = true; break;
    } catch { await delay(1000); }
  }
  assert.ok(ready, "Dedicated source database must be ready");
  await query(source, fixtureSQL);
  const before = JSON.parse((await query(source, snapshotSQL)).stdout);
  const database = databaseClient({ prefix: ["exec", "-i", source] });
  const backup = await createBackup({ outputDir, database });
  assert.equal(backup.manifest.warnings, false);
  await verifyBackup(backup.directory);
  const restored = await restoreBackup(backup.directory, {
    trusted: true, onCreated: (resource) => { recovery = resource; },
  });
  assert.deepEqual(restored.counts, {
    clients: 1, users: 1, scans: 1, assets: 1, findings: 1, workflows: 1,
    ai_analyses: 1, tickets: 1, audit_events: 1,
  });
  assert.deepEqual(JSON.parse((await query(restored.container, snapshotSQL)).stdout), before);
  assert.deepEqual(JSON.parse((await query(source, snapshotSQL)).stdout), before);
  const network = await docker(["inspect", "--format", "{{.HostConfig.NetworkMode}}", restored.container]);
  assert.equal(network.stdout, "none");
  const ports = await docker(["port", restored.container]);
  assert.equal(ports.stdout, "");
  // Restore must preserve identity sequence positions, not merely the visible rows.
  const inserted = await query(restored.container, "INSERT INTO vm.host (cliente_id, endereco) VALUES (1, '192.0.2.124') RETURNING id;");
  assert.ok(inserted.stdout.startsWith("2\n"));
});
