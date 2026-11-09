import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { test } from "node:test";

import { createBackup, databaseClient, parseArguments, restoreBackup, verifyBackup } from "./backup.mjs";

const syntheticArchive = Buffer.from("PGDMPsynthetic-archive-not-a-real-database");
const counts = { clients: 1, users: 1, scans: 2, assets: 1, findings: 3, workflows: 3, ai_analyses: 1, tickets: 1, audit_events: 2 };
const database = {
  version: async () => ({ stdout: "170006" }),
  dump: async (output) => { await pipeline(Readable.from([syntheticArchive]), output); return { warned: false }; },
};

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "wvm-backup-unit-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test("creates unique private backups, preserves existing files and verifies integrity offline", async (t) => {
  const outputDir = await fixture(t);
  const first = await createBackup({ outputDir, database });
  const second = await createBackup({ outputDir, database });
  assert.notEqual(first.directory, second.directory);
  assert.deepEqual(await readFile(join(first.directory, "database.dump")), syntheticArchive);
  assert.equal((await verifyBackup(first.directory)).manifest.bytes, syntheticArchive.length);
  assert.equal(first.manifest.encrypted, false);
  assert.equal(first.manifest.warnings, false);
  if (process.platform !== "win32") {
    assert.equal((await stat(first.directory)).mode & 0o777, 0o700);
    for (const file of ["database.dump", "manifest.json"]) assert.equal((await stat(join(first.directory, file))).mode & 0o777, 0o600);
  }
});

test("records dump warnings without exposing private stderr", async (t) => {
  const result = await createBackup({ outputDir: await fixture(t), database: {
    ...database, dump: async (out) => { await database.dump(out); return { warned: true }; },
  } });
  assert.equal(result.manifest.warnings, true);
});

test("incomplete dump never has a successful manifest", async (t) => {
  const outputDir = await fixture(t);
  await assert.rejects(createBackup({ outputDir, database: {
    ...database, dump: async (out) => { await pipeline(Readable.from(["PGDMPpartial"]), out); throw Error("private-database-error"); },
  } }), (error) => error.message.includes("Backup incompleto") && !error.message.includes("private-database-error"));
  const [child] = await readdir(outputDir);
  assert.deepEqual(await readdir(join(outputDir, child)), ["database.dump.partial"]);
});

test("rejects wrong PostgreSQL version before creating any backup file", async (t) => {
  const outputDir = await fixture(t);
  await assert.rejects(createBackup({ outputDir, database: { ...database, version: async () => ({ stdout: "180001" }) } }));
  assert.deepEqual(await readdir(outputDir), []);
});

for (const corruption of ["size", "hash", "header", "manifest"]) {
  test(`rejects ${corruption} corruption before contacting Docker`, async (t) => {
    const { directory } = await createBackup({ outputDir: await fixture(t), database });
    const archive = join(directory, "database.dump");
    if (corruption === "size") await writeFile(archive, "PGDMPshort");
    if (corruption === "hash") await writeFile(archive, Buffer.from(syntheticArchive.toString().replace("synthetic", "corrupted")));
    if (corruption === "header") await writeFile(archive, Buffer.from(syntheticArchive.toString().replace("PGDMP", "WRONG")));
    if (corruption === "manifest") await writeFile(join(directory, "manifest.json"), '{"version":999}');
    let called = false;
    await assert.rejects(restoreBackup(directory, { trusted: true, run: async () => { called = true; } }));
    assert.equal(called, false);
  });
}

test("refuses symlink archives", { skip: process.platform === "win32" }, async (t) => {
  const outputDir = await fixture(t);
  const { directory } = await createBackup({ outputDir, database });
  const file = join(directory, "database.dump");
  const external = join(outputDir, "original.dump");
  await writeFile(external, syntheticArchive);
  await rm(file);
  await symlink(external, file);
  await assert.rejects(verifyBackup(directory));
  assert.deepEqual(await readFile(external), syntheticArchive);
});

test("requires explicit trust before restoring SQL from an archive", async () => {
  let calls = 0;
  await assert.rejects(restoreBackup("unused", { run: async () => { calls += 1; } }), /--trusted/);
  assert.equal(calls, 0);
});

function restoreRunner({ fail = false, collision = false } = {}) {
  const calls = [];
  return { calls, run: async (args, options = {}) => {
    calls.push({ args, options });
    if (collision && args[0] === "volume" && args[1] === "ls") return { stdout: "existing-volume" };
    if (options.input) {
      const chunks = [];
      for await (const chunk of options.input) chunks.push(chunk);
      assert.deepEqual(Buffer.concat(chunks), syntheticArchive);
      if (fail) throw Error("private SQL must not be printed");
    }
    return { stdout: args.at(-1)?.startsWith("SELECT json_build_object") ? JSON.stringify(counts) : "", warned: false };
  } };
}

test("restores only into generated isolated resources, without clean/create or published ports", async (t) => {
  const { directory } = await createBackup({ outputDir: await fixture(t), database });
  const fake = restoreRunner();
  const result = await restoreBackup(directory, { trusted: true, run: fake.run, wait: async () => {} });
  assert.deepEqual(result.counts, counts);
  assert.match(result.container, /^wvm-restore-[a-f0-9]{16}$/);
  const start = fake.calls.find((call) => call.args[0] === "run");
  assert.equal(start.args[start.args.indexOf("--network") + 1], "none");
  assert.equal(start.options.env.POSTGRES_PASSWORD.length, 64);
  assert.ok(!start.args.includes(start.options.env.POSTGRES_PASSWORD));
  assert.ok(!start.args.includes("--publish") && !start.args.includes("-p"));
  const commands = fake.calls.map((call) => call.args.join(" ")).join("\n");
  assert.ok(!commands.includes("--clean") && !commands.includes("--create"));
  assert.ok(commands.includes("--single-transaction"));
  assert.ok(!commands.includes("compose"));
});

test("failure stops only the new recovery container and retains its volume", async (t) => {
  const { directory } = await createBackup({ outputDir: await fixture(t), database });
  const fake = restoreRunner({ fail: true });
  await assert.rejects(restoreBackup(directory, { trusted: true, run: fake.run }), (error) =>
    error.message.includes("banco original foi preservado") && !error.message.includes("private SQL"));
  assert.equal(fake.calls.at(-1).args[0], "stop");
  assert.ok(fake.calls.every((call) => !call.args.includes("rm")));
});

test("resource collision never attaches, stops or removes existing resources", async (t) => {
  const { directory } = await createBackup({ outputDir: await fixture(t), database });
  const fake = restoreRunner({ collision: true });
  await assert.rejects(restoreBackup(directory, { trusted: true, run: fake.run }));
  assert.ok(fake.calls.every((call) => ["ps", "volume"].includes(call.args[0])));
  assert.ok(fake.calls.every((call) => !call.args.includes("create")));
});

test("database commands use container credentials, not keys or a host .env", async () => {
  const calls = [];
  const client = databaseClient({ run: async (args) => { calls.push(args); return { stdout: "170006" }; } });
  await client.version();
  await client.dump({});
  assert.deepEqual(calls[0].slice(0, 4), ["compose", "exec", "-T", "database"]);
  assert.ok(calls[1].at(-1).includes("pg_dump"));
  assert.ok(!calls.flat().join(" ").includes(".env"));
});

test("parses only the supported CLI actions and options", () => {
  assert.deepEqual(parseArguments(["create"]), { command: "create" });
  assert.equal(parseArguments(["restore", "backups/example", "--trusted"]).trusted, true);
  for (const args of [["drop"], ["create", "--force"], ["restore", "x", "--clean"], ["verify", "x", "--trusted"], ["restore", "--trusted"]]) {
    assert.throws(() => parseArguments(args));
  }
});
