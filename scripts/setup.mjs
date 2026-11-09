import { randomBytes } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseEnv } from "node:util";

const root = fileURLToPath(new URL("../", import.meta.url));

export function createLocalConfiguration(template) {
  const example = parseEnv(template);
  for (const name of ["POSTGRES_USER", "POSTGRES_DB"]) {
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(example[name] ?? "")) {
      throw new Error("Modelo de configuração inválido.");
    }
  }
  const password = randomBytes(24).toString("hex");
  const values = {
    APP_ENV: "development",
    APP_SECRET_KEY: randomBytes(32).toString("hex"),
    POSTGRES_PASSWORD: password,
    DATABASE_URL: `postgresql+asyncpg://${example.POSTGRES_USER}:${password}@database:5432/${example.POSTGRES_DB}`,
    BOOTSTRAP_ADMIN_PASSWORD: randomBytes(24).toString("hex"),
    AI_PROVIDER: "disabled",
    ANTHROPIC_API_KEY: "",
    ANTHROPIC_WORKSPACE_ID: "",
    OPENAI_API_KEY: "",
    TICKET_PROVIDER: "disabled",
    JIRA_API_TOKEN: "",
  };
  if (Object.keys(values).some((key) => !Object.hasOwn(example, key))) {
    throw new Error("Modelo de configuração incompleto.");
  }
  return template.split(/\r?\n/).map((line) => {
    const key = line.match(/^([A-Z_]+)=/)?.[1];
    return Object.hasOwn(values, key) ? `${key}=${values[key]}` : line;
  }).join("\n");
}

export function setupLocal({ cwd = root } = {}) {
  const destination = join(cwd, ".env");
  try {
    // Do not read, overwrite or follow an existing .env (including symlinks).
    lstatSync(destination);
    return { created: false };
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const configured = createLocalConfiguration(readFileSync(join(cwd, ".env.example"), "utf8"));
  try {
    writeFileSync(destination, configured, { flag: "wx", mode: 0o600 });
    return { created: true };
  } catch (error) {
    if (error.code === "EEXIST") return { created: false };
    throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { created } = setupLocal();
    console.log(created
      ? ".env criado com senhas e segredo de sessão aleatórios. Nenhum segredo foi exibido."
      : ".env já existe e foi preservado, sem alterar chaves ou senhas.");
    console.log("Consulte BOOTSTRAP_ADMIN_EMAIL e BOOTSTRAP_ADMIN_PASSWORD no .env para entrar.");
    console.log("A criação inicial mantém IA e Jira desativados. Ative-os somente após configurar as credenciais.");
    console.log("Próximo passo: docker compose up -d --build. Diagnóstico: npm run doctor.");
  } catch {
    console.error("Não foi possível preparar o .env. Confira .env.example e as permissões da pasta; nenhum segredo será exibido.");
    process.exitCode = 1;
  }
}
