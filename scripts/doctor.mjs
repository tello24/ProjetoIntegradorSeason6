import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseEnv } from "node:util";

const root = fileURLToPath(new URL("../", import.meta.url));
const result = (id, status, message, hint = "") => ({ id, status, message, hint });

export function parseOrigins(value) {
  const parsed = value.trim().startsWith("[") ? JSON.parse(value) : value.split(",");
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) {
    throw new Error("Invalid origin list");
  }
  return parsed.map((item) => item.trim()).filter(Boolean);
}

function httpUrl(value) {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.hash || url.search) {
    throw new Error("Invalid URL");
  }
  return url;
}

export function checkConfiguration(env) {
  const checks = [];
  const add = (id, valid, message, hint) => checks.push(result(id, valid ? "ok" : "error", message, valid ? "" : hint));
  add("secret", (env.APP_SECRET_KEY?.length ?? 0) >= 32,
    "Segredo de sessão com pelo menos 32 caracteres.", "Defina APP_SECRET_KEY com um valor aleatório próprio; não envie esse valor no diagnóstico.");
  if (/development-only|change-me/i.test(env.APP_SECRET_KEY ?? "")) {
    checks.push(result("default-secret", "warning", "O segredo de sessão ainda é um exemplo.", "Substitua APP_SECRET_KEY por um valor aleatório próprio."));
  }
  const local = (env.APP_ENV ?? "development").toLowerCase() === "development";
  if (local) {
    add("admin-email", /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(env.BOOTSTRAP_ADMIN_EMAIL ?? ""),
      "E-mail da conta inicial preenchido.", "Preencha BOOTSTRAP_ADMIN_EMAIL para criar a conta local.");
    add("admin-password", (env.BOOTSTRAP_ADMIN_PASSWORD?.trim().length ?? 0) >= 12,
      "Senha da conta inicial com pelo menos 12 caracteres.", "Defina BOOTSTRAP_ADMIN_PASSWORD com 12 caracteres ou mais. Uma senha menor impede a inicialização da API.");
  } else {
    checks.push(result("bootstrap", "warning", "A criação da conta local está desativada fora de development.", "Para desenvolvimento local, confira APP_ENV=development. Não altere um ambiente de produção por esse motivo."));
  }
  try {
    const database = new URL(env.DATABASE_URL);
    add("database-url", database.protocol === "postgresql+asyncpg:" && database.hostname === "database" && (database.port || "5432") === "5432",
      "Endereço do PostgreSQL compatível com o Docker Compose local.", "No Compose padrão, DATABASE_URL usa postgresql+asyncpg e o host database:5432, não localhost.");
    add("database-credentials", decodeURIComponent(database.username) === env.POSTGRES_USER &&
      decodeURIComponent(database.password) === env.POSTGRES_PASSWORD &&
      decodeURIComponent(database.pathname.slice(1)) === env.POSTGRES_DB,
    "Credenciais do banco consistentes entre as variáveis.", "Confira POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD e DATABASE_URL. Alterar a senha no .env não altera a senha de um volume PostgreSQL já criado. Não apague o volume.");
  } catch {
    checks.push(result("database-url", "error", "DATABASE_URL ausente ou inválida.", "Compare o formato com .env.example, sem compartilhar a senha."));
  }
  try {
    const web = httpUrl(env.APP_PUBLIC_URL ?? "http://localhost:3000");
    const api = httpUrl(env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1");
    const internal = httpUrl(env.INTERNAL_API_URL ?? "http://api:8000/api/v1");
    add("web-origin", web.pathname === "/", "Origem da interface sem caminho adicional.", "APP_PUBLIC_URL deve ser a origem da aplicação, por exemplo http://localhost:3000.");
    add("public-api", api.pathname === "/api/v1" && api.hostname !== "api",
      "Endereço público da API válido para o navegador.", "Use NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1 no computador que executa o Docker. O navegador não resolve o nome interno api.");
    add("cookie-host", web.hostname === api.hostname,
      "Interface e API usam o mesmo host para o cookie de sessão.", "Não misture localhost e 127.0.0.1 entre APP_PUBLIC_URL e NEXT_PUBLIC_API_URL. O frontend precisa receber o cookie criado pela API.");
    add("internal-api", internal.hostname === "api" && internal.pathname === "/api/v1" && internal.port === "8000",
      "Endereço interno da API compatível com o Docker Compose.", "Use INTERNAL_API_URL=http://api:8000/api/v1 no Compose padrão.");
    const origins = parseOrigins(env.API_CORS_ORIGINS ?? "http://localhost:3000");
    add("cors-config", origins.includes(web.origin), "CORS contém a origem da interface.", "Inclua a origem exata de APP_PUBLIC_URL em API_CORS_ORIGINS. localhost e 127.0.0.1 são origens diferentes.");
    if (!local && web.protocol === "http:") {
      checks.push(result("secure-cookie", "warning", "Cookies seguros e acesso HTTP podem impedir o login.", "Use HTTPS em produção; para o ambiente local, use APP_ENV=development."));
    }
  } catch {
    checks.push(result("web-config", "error", "Endereço da aplicação ou lista de CORS inválida.", "Confira APP_PUBLIC_URL, NEXT_PUBLIC_API_URL, INTERNAL_API_URL e API_CORS_ORIGINS no modelo. Não coloque credenciais nessas URLs."));
  }
  if (env.SESSION_COOKIE_NAME && env.SESSION_COOKIE_NAME !== "ng_session") {
    checks.push(result("cookie-name", "error", "Nome do cookie incompatível com o frontend atual.", "Mantenha SESSION_COOKIE_NAME=ng_session nesta versão."));
  }
  const provider = env.AI_PROVIDER?.trim() || "disabled";
  if (provider === "disabled") {
    checks.push(result("ai-config", "warning", "A IA está desativada; somente o plano-base está disponível.", "Para usar Claude, escolha AI_PROVIDER=anthropic e preencha ANTHROPIC_API_KEY no .env local. Recrie a API após alterar o arquivo."));
  } else if (["anthropic", "openai"].includes(provider)) {
    const prefix = provider.toUpperCase();
    add("ai-key", Boolean(env[`${prefix}_API_KEY`]?.trim()),
      "Chave do provedor de IA preenchida (validade e saldo não testados).", `Preencha ${prefix}_API_KEY no .env local, nunca no código ou no Git. Recrie a API após alterar o arquivo.`);
    if (env[`${prefix}_MODEL`] !== undefined) {
      add("ai-model", Boolean(env[`${prefix}_MODEL`].trim()), "Modelo de IA preenchido.", `Confira ${prefix}_MODEL; esta verificação não confirma acesso ao modelo.`);
    }
    for (const [key, min, max] of [["AI_TIMEOUT_SECONDS", 5, 120], ["AI_MAX_OUTPUT_TOKENS", 500, 8192]]) {
      if (env[key] !== undefined) {
        const value = Number(env[key]);
        add(`ai-${key.toLowerCase()}`, Number.isInteger(value) && value >= min && value <= max,
          `${key} dentro da faixa permitida.`, `Defina ${key} entre ${min} e ${max}.`);
      }
    }
  } else {
    checks.push(result("ai-provider", "error", "Provedor de IA inválido.", "Use AI_PROVIDER=disabled, anthropic ou openai."));
  }
  return checks;
}

export function parseServices(output) {
  const trimmed = output.trim();
  if (!trimmed) return [];
  const parsed = trimmed.startsWith("[") ? JSON.parse(trimmed) : trimmed.split(/\r?\n/).map((line) => JSON.parse(line));
  if (!Array.isArray(parsed)) throw new Error("Invalid service list");
  return parsed;
}

export function checkServices(services) {
  return ["database", "migrations", "api", "web"].map((name) => {
    const matches = services.filter((item) => item.Service === name);
    if (!matches.length) return result(`service-${name}`, "error", `Serviço ${name} não encontrado neste projeto.`, "Na pasta do projeto, execute docker compose up -d --build.");
    const healthy = matches.every((item) =>
      name === "migrations"
        ? item.State === "exited" && Number(item.ExitCode) === 0
        : item.State === "running" && (!item.Health || item.Health === "healthy"));
    return result(`service-${name}`, healthy ? "ok" : "error",
      healthy ? `Serviço ${name}: ${name === "migrations" ? "concluído (saída 0, esperado)" : "em execução"}.` : `Serviço ${name} parado, inicializando ou sem saúde confirmada.`,
      healthy ? "" : `Consulte docker compose logs --tail=60 ${name}. Remova dados sensíveis antes de compartilhar os registros.`);
  });
}

export async function checkHttp(env, request = fetch) {
  const checks = [];
  let api, web;
  try {
    api = httpUrl(env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1");
    web = httpUrl(env.APP_PUBLIC_URL ?? "http://localhost:3000");
    if (![api, web].every((url) => ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) {
      return [result("local-probes", "warning", "Testes HTTP omitidos: este diagnóstico só consulta endereços locais.", "Verifique o acesso remoto com o responsável pela implantação.")];
    }
  } catch {
    return [result("local-probes", "error", "Não foi possível validar os endereços para os testes locais.")];
  }
  const base = api.href.replace(/\/$/, "");
  const get = (url, options = {}) => request(url, { redirect: "error", signal: AbortSignal.timeout(4000), ...options });
  try {
    const response = await get(`${base}/health/ready`);
    const payload = await response.json();
    if (payload.service !== "neoguardian-insight-api") throw new Error("Different service");
    if (response.ok && payload.status === "ready") {
      checks.push(result("api-ready", "ok", "API, conexão com o banco e esquema básico disponíveis."));
    } else {
      const databaseFailed = payload.checks?.database === "unavailable";
      checks.push(result("api-ready", "error", databaseFailed ? "A API respondeu, mas não conseguiu consultar o banco." : "A API respondeu, mas não confirmou o esquema necessário.", databaseFailed ? "Confira o serviço database e as credenciais locais." : "Confira o serviço migrations e os registros da API; não remova o volume de dados."));
    }
  } catch {
    checks.push(result("api-ready", "error", "A prontidão da API não pôde ser confirmada.", "Confira os serviços, a porta 8000 e NEXT_PUBLIC_API_URL. Se a API for de uma versão anterior, reconstrua a imagem."));
  }
  try {
    const response = await get(`${base}/auth/login`, {
      method: "OPTIONS",
      headers: { Origin: web.origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type" },
    });
    const methods = (response.headers.get("access-control-allow-methods") ?? "").toUpperCase().split(",").map((item) => item.trim());
    const headers = (response.headers.get("access-control-allow-headers") ?? "").toLowerCase().split(",").map((item) => item.trim());
    const allowed = response.ok && response.headers.get("access-control-allow-origin") === web.origin && response.headers.get("access-control-allow-credentials") === "true" && methods.includes("POST") && headers.includes("content-type");
    checks.push(result("cors-live", allowed ? "ok" : "error", allowed ? "API autoriza a comunicação do navegador com cookies." : "A autorização CORS da API não foi confirmada.", allowed ? "" : "Confira API_CORS_ORIGINS e a URL aberta no navegador; recrie a API após alterar o .env."));
  } catch {
    checks.push(result("cors-live", "warning", "Não foi possível testar CORS enquanto a API estiver inacessível."));
  }
  try {
    const response = await get(new URL("/login", web));
    checks.push(result("web-live", response.ok ? "ok" : "error", response.ok ? "Página de login acessível." : "A interface respondeu com erro.", response.ok ? "" : "Confira os registros do serviço web."));
  } catch {
    checks.push(result("web-live", "error", "A página de login não pôde ser acessada.", "Confira o serviço web e a porta 3000."));
  }
  return checks;
}

export async function diagnose({ cwd = root, processEnv = process.env, run, request = fetch, read = readFileSync } = {}) {
  const checks = [];
  let env;
  try {
    env = parseEnv(read(`${cwd}/.env`, "utf8"));
    for (const key of Object.keys(env)) {
      if (processEnv[key] !== undefined) env[key] = processEnv[key];
    }
    checks.push(result("env-file", "ok", "Arquivo .env encontrado; valores não serão exibidos."));
    checks.push(...checkConfiguration(env));
  } catch {
    checks.push(result("env-file", "error", "Arquivo .env ausente ou ilegível.", "Duplique .env.example como .env e preencha a configuração local. O Git não inclui seu .env. Não sobrescreva um arquivo existente."));
  }
  const execute = run ?? ((args) => {
    try {
      return { ok: true, output: execFileSync("docker", args, { cwd, encoding: "utf8", timeout: 10000, stdio: ["ignore", "pipe", "pipe"] }) };
    } catch { return { ok: false }; }
  });
  if (!execute(["--version"]).ok) {
    checks.push(result("docker", "error", "Docker não encontrado no terminal.", "Instale o Docker Desktop e reabra o terminal."));
  } else if (!execute(["info", "--format", "{{.ServerVersion}}"]).ok) {
    checks.push(result("docker", "error", "Não foi possível acessar o mecanismo do Docker.", "Abra o Docker Desktop e confira as permissões do terminal."));
  } else if (!execute(["compose", "version"]).ok) {
    checks.push(result("compose", "error", "Docker Compose indisponível.", "Instale uma versão do Docker Desktop com Compose v2."));
  } else {
    checks.push(result("docker", "ok", "Docker e Compose disponíveis."));
    if (env) {
      const state = execute(["compose", "ps", "--all", "--format", "json"]);
      try {
        if (!state.ok) throw new Error("Compose error");
        checks.push(...checkServices(parseServices(state.output)));
      } catch {
        checks.push(result("compose-state", "error", "Não foi possível ler os serviços deste projeto.", "Verifique se o terminal está na raiz do repositório e se o Compose aceita o .env."));
      }
    }
  }
  if (env) checks.push(...await checkHttp(env, request));
  return checks;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const checks = await diagnose();
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify({ checks }, null, 2));
  } else {
    console.log("WVM — diagnóstico local (somente leitura; não imprime segredos)");
    for (const check of checks) {
      console.log(`[${{ ok: "OK", warning: "ATENÇÃO", error: "ERRO" }[check.status]}] ${check.message}`);
      if (check.hint) console.log(`  ${check.hint}`);
    }
    console.log("Este diagnóstico não comprova a senha de login nem a saúde de todas as funções da aplicação.");
  }
  process.exitCode = checks.some((check) => check.status === "error") ? 1 : 0;
}
