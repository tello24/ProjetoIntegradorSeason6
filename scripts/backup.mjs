import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { lstat, mkdir, mkdtemp, open, readFile, rename, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { Readable, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const root = fileURLToPath(new URL("../", import.meta.url));
const dumpFile = "database.dump";
const manifestFile = "manifest.json";
const image = "postgres:17-alpine";
const credentials = 'export PGPASSWORD="$POSTGRES_PASSWORD"; ';
const connection = '--username="$POSTGRES_USER" --dbname="$POSTGRES_DB"';
const versionCommand = `${credentials}exec psql ${connection} -X -At -v ON_ERROR_STOP=1 -c 'SHOW server_version_num'`;
const dumpCommand = `${credentials}exec pg_dump ${connection} --format=custom --no-owner --no-acl`;
const restoreCommand = `${credentials}exec pg_restore ${connection} --no-owner --no-acl --exit-on-error --single-transaction`;
const summarySQL = `SELECT json_build_object(
  'clients', (SELECT count(*) FROM vm.cliente),
  'users', (SELECT count(*) FROM app.usuario),
  'scans', (SELECT count(*) FROM vm.scan),
  'assets', (SELECT count(*) FROM vm.host),
  'findings', (SELECT count(*) FROM vm.achado),
  'workflows', (SELECT count(*) FROM app.vulnerabilidade_tratamento),
  'ai_analyses', (SELECT count(*) FROM app.vulnerabilidade_analise_ia),
  'tickets', (SELECT count(*) FROM app.vulnerabilidade_ticket),
  'audit_events', (SELECT count(*) FROM app.evento_auditoria)
)`;

// Capture neither stderr nor data on errors: database tools can include private SQL.
export async function docker(args, { cwd = root, input, output, env = {}, timeoutMs = 600_000 } = {}) {
  const child = spawn("docker", args, {
    cwd, env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"], windowsHide: true,
  });
  let captured = "";
  let warned = false;
  let timer;
  const completed = new Promise((resolveExit, reject) => {
    child.once("error", () => reject(new Error("Não foi possível executar o Docker.")));
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolveExit();
      else reject(new Error("A operação do Docker/PostgreSQL falhou. Nenhum detalhe sensível foi exibido."));
    });
    timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    timer.unref();
  });
  child.stderr.on("data", () => { warned = true; });
  const destination = output ?? new Writable({ write(chunk, _, callback) {
    if (captured.length + chunk.length > 65_536) {
      callback(new Error("Saída de diagnóstico excedeu o limite seguro."));
    } else { captured += chunk.toString(); callback(); }
  } });
  const tasks = [completed, pipeline(child.stdout, destination)];
  if (input) tasks.push(pipeline(typeof input === "string" ? Readable.from([input]) : input, child.stdin));
  else child.stdin.end();
  try {
    await Promise.all(tasks);
    return { stdout: captured.trim(), warned };
  } catch {
    child.kill("SIGKILL");
    await Promise.allSettled(tasks);
    throw new Error("A operação do Docker/PostgreSQL falhou. Confira o Docker e o espaço em disco; nenhum segredo foi exibido.");
  } finally {
    clearTimeout(timer);
  }
}

export function databaseClient({ run = docker, prefix = ["compose", "exec", "-T", "database"] } = {}) {
  return {
    version: () => run([...prefix, "sh", "-c", versionCommand]),
    dump: (output) => run([...prefix, "sh", "-c", dumpCommand], { output }),
  };
}

async function regularFile(path, maxBytes = Infinity) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size > maxBytes) throw new Error("Arquivo inválido ou link simbólico não permitido.");
  return stat;
}

async function archiveDigest(path) {
  await regularFile(path);
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function checkHeader(path) {
  const handle = await open(path, "r");
  try {
    const magic = Buffer.alloc(5);
    const { bytesRead } = await handle.read(magic, 0, 5, 0);
    if (bytesRead !== 5 || magic.toString() !== "PGDMP") throw new Error("Backup não está no formato esperado do PostgreSQL.");
  } finally { await handle.close(); }
}

export async function createBackup({ outputDir = join(root, "backups"), database = databaseClient() } = {}) {
  const version = await database.version();
  if (!/^17\d{4}$/.test(version.stdout)) throw new Error("Este procedimento requer PostgreSQL 17, como no Compose do projeto.");
  await mkdir(outputDir, { recursive: true, mode: 0o700 });
  if (!(await lstat(outputDir)).isDirectory()) throw new Error("A pasta de backups não pode ser um link simbólico.");
  const stamp = new Date().toISOString().replaceAll(/[:.]/g, "-");
  const directory = await mkdtemp(join(resolve(outputDir), `wvm-${stamp}-`));
  const partial = join(directory, "database.dump.partial");
  const output = createWriteStream(partial, { flags: "wx", mode: 0o600 });
  try {
    const result = await database.dump(output);
    const stat = await regularFile(partial);
    await checkHeader(partial);
    const digest = await archiveDigest(partial);
    await rename(partial, join(directory, dumpFile));
    const manifest = {
      application: "WVM", version: 1, created_at: new Date().toISOString(),
      format: "postgresql-custom", postgres_version: Number(version.stdout),
      bytes: stat.size, sha256: digest, warnings: Boolean(result.warned),
      encrypted: false,
    };
    await writeFile(join(directory, manifestFile), JSON.stringify(manifest, null, 2) + "\n", { flag: "wx", mode: 0o600 });
    return { directory, manifest };
  } catch {
    output.destroy();
    // Keep the incomplete directory for diagnosis, never label it as a valid backup.
    throw new Error(`Backup incompleto. O banco original não foi alterado. Arquivos parciais protegidos em: ${directory}`);
  }
}

export async function verifyBackup(directory) {
  directory = resolve(directory);
  if (!(await lstat(directory)).isDirectory()) throw new Error("A pasta do backup deve ser um diretório, não um link.");
  const manifestPath = join(directory, manifestFile);
  await regularFile(manifestPath, 8_192);
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  if (manifest.application !== "WVM" || manifest.version !== 1 || manifest.format !== "postgresql-custom"
      || !Number.isInteger(manifest.postgres_version) || manifest.postgres_version < 170000 || manifest.postgres_version >= 180000
      || !Number.isSafeInteger(manifest.bytes) || manifest.bytes < 5 || !/^[a-f0-9]{64}$/.test(manifest.sha256)) {
    throw new Error("Manifesto de backup inválido ou incompatível.");
  }
  const archive = join(directory, dumpFile);
  const stat = await regularFile(archive);
  if (stat.size !== manifest.bytes) throw new Error("O tamanho do backup mudou; recuperação bloqueada.");
  await checkHeader(archive);
  if (await archiveDigest(archive) !== manifest.sha256) throw new Error("A integridade do backup não confere; recuperação bloqueada.");
  return { directory, archive, manifest };
}

export async function restoreBackup(directory, { trusted = false, run = docker, wait = delay, onProgress = () => {}, onCreated = () => {} } = {}) {
  if (!trusted) throw new Error("Use --trusted somente para um backup próprio e confiável. A restauração executa SQL do arquivo.");
  const verified = await verifyBackup(directory);
  const suffix = randomBytes(8).toString("hex");
  const container = `wvm-restore-${suffix}`;
  const volume = `${container}-data`;
  const password = randomBytes(32).toString("hex");
  let created = false;
  try {
    // Refuse collisions. Never attach an existing volume or replace an existing container.
    const volumes = await run(["volume", "ls", "--filter", `name=^${volume}$`, "--format", "{{.Name}}"]);
    const containers = await run(["ps", "-a", "--filter", `name=^/${container}$`, "--format", "{{.Names}}"]);
    if (volumes.stdout || containers.stdout) throw new Error("Nome de recuperação já existente.");
    await run(["volume", "create", "--label", "wvm.recovery=true", volume]);
    onCreated({ container, volume });
    await run([
      "run", "--detach", "--name", container, "--network", "none",
      "--label", "wvm.recovery=true", "--mount", `type=volume,source=${volume},target=/var/lib/postgresql/data`,
      "--env", "POSTGRES_USER=wvm_restore", "--env", "POSTGRES_DB=wvm_restore",
      "--env", "POSTGRES_PASSWORD", image,
    ], { env: { POSTGRES_PASSWORD: password } });
    created = true;
    onProgress("Banco de recuperação criado sem rede externa e sem portas publicadas.");
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      try {
        // The image's temporary initialization server does not listen on TCP.
        await run(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "wvm_restore", "-d", "wvm_restore"], { timeoutMs: 10_000 });
        ready = true; break;
      } catch { await wait(1000); }
    }
    if (!ready) throw new Error("O banco de recuperação não iniciou no prazo.");
    onProgress("Restaurando a cópia isolada; o banco da aplicação não será modificado.");
    // Never --clean, --create, user-supplied connection strings, or the live database.
    await run(["exec", "-i", container, "sh", "-c", restoreCommand], { input: createReadStream(verified.archive) });
    const summary = await run([
      "exec", container, "sh", "-c",
      `${credentials}exec psql ${connection} -X -At -v ON_ERROR_STOP=1 -c "$1"`, "sh", summarySQL,
    ]);
    const counts = JSON.parse(summary.stdout);
    const fields = ["clients", "users", "scans", "assets", "findings", "workflows", "ai_analyses", "tickets", "audit_events"];
    if (fields.some((key) => !Number.isSafeInteger(counts[key]) || counts[key] < 0)) throw new Error("Verificação da cópia restaurada falhou.");
    return { container, volume, counts, source: verified.directory };
  } catch {
    if (created) await run(["stop", container]).catch(() => {});
    throw new Error(`A recuperação isolada não foi concluída. O banco original foi preservado. Recursos reservados: ${container}, ${volume}. Não foram removidos automaticamente.`);
  }
}

export function parseArguments(args) {
  const [command, ...rest] = args;
  if (!["create", "verify", "restore"].includes(command)) throw new Error("Use create, verify ou restore.");
  if (command === "create") {
    if (rest.length === 0) return { command };
    if (rest.length === 2 && rest[0] === "--output" && rest[1]) return { command, outputDir: resolve(rest[1]) };
  } else {
    const trusted = rest.includes("--trusted");
    const paths = rest.filter((value) => value !== "--trusted");
    if (paths.length === 1 && !paths[0].startsWith("-") && (command === "restore" || !trusted)
        && rest.filter((value) => value === "--trusted").length <= 1) {
      return { command, directory: resolve(paths[0]), trusted };
    }
  }
  throw new Error("Argumentos inválidos. Use backup, backup:verify -- PASTA ou backup:restore -- PASTA --trusted.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const options = parseArguments(process.argv.slice(2));
    if (options.command === "create") {
      console.log("Criando backup local do banco. Nenhum arquivo .env será copiado.");
      const result = await createBackup(options);
      console.log(`Backup criado em: ${result.directory}`);
      console.log(`Tamanho: ${result.manifest.bytes} bytes. Integridade SHA-256 registrada.`);
      if (result.manifest.warnings) console.log("ATENÇÃO: o PostgreSQL emitiu avisos. Valide a recuperação antes de depender desta cópia.");
      console.log("Contém dados sensíveis e NÃO está criptografado. Guarde em armazenamento protegido; não envie ao Git.");
    } else if (options.command === "verify") {
      await verifyBackup(options.directory);
      console.log("Integridade conferida. Isso não substitui um teste de restauração nem comprova a origem do arquivo.");
    } else {
      const result = await restoreBackup(options.directory, { ...options, onProgress: console.log });
      console.log(`Cópia restaurada: ${result.container}\nVolume persistente: ${result.volume}`);
      console.log(`Contagens verificadas: ${JSON.stringify(result.counts)}`);
      console.log("A aplicação continua usando o banco original. Nenhuma chave de IA foi configurada na cópia.");
    }
  } catch (error) {
    // Only authored messages; filesystem/JSON errors can include private paths or text.
    const safe = error instanceof Error && !error.code && !["SyntaxError", "TypeError"].includes(error.name);
    console.error(safe ? error.message : "Não foi possível acessar ou validar o backup. Confira os caminhos e as permissões.");
    process.exitCode = 1;
  }
}
