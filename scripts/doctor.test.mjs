import assert from "node:assert/strict";
import { test } from "node:test";
import { checkConfiguration, checkHttp, checkServices, diagnose, parseOrigins, parseServices } from "./doctor.mjs";

const env = {
  APP_ENV: "development", APP_SECRET_KEY: "only-for-tests-12345678901234567890",
  BOOTSTRAP_ADMIN_EMAIL: "admin@example.com", BOOTSTRAP_ADMIN_PASSWORD: "only-for-tests-password",
  POSTGRES_DB: "wvm", POSTGRES_USER: "user", POSTGRES_PASSWORD: "private-test-value",
  DATABASE_URL: "postgresql+asyncpg://user:private-test-value@database:5432/wvm",
  API_CORS_ORIGINS: '["http://localhost:3000"]', APP_PUBLIC_URL: "http://localhost:3000",
  NEXT_PUBLIC_API_URL: "http://localhost:8000/api/v1", INTERNAL_API_URL: "http://api:8000/api/v1",
};
const errors = (checks) => checks.filter((check) => check.status === "error");

test("accepts the local configuration and both CORS formats", () => {
  assert.equal(errors(checkConfiguration(env)).length, 0);
  assert.deepEqual(parseOrigins("http://localhost:3000, http://127.0.0.1:3000"), ["http://localhost:3000", "http://127.0.0.1:3000"]);
  assert.throws(() => parseOrigins('[true]'));
});

for (const [key, value, id] of [
  ["BOOTSTRAP_ADMIN_PASSWORD", "short", "admin-password"],
  ["BOOTSTRAP_ADMIN_EMAIL", "", "admin-email"],
  ["APP_SECRET_KEY", "short", "secret"],
  ["POSTGRES_PASSWORD", "different", "database-credentials"],
  ["DATABASE_URL", "not-a-url", "database-url"],
  ["API_CORS_ORIGINS", "http://127.0.0.1:3000", "cors-config"],
  ["API_CORS_ORIGINS", "[invalid", "web-config"],
  ["NEXT_PUBLIC_API_URL", "http://api:8000/api/v1", "public-api"],
  ["NEXT_PUBLIC_API_URL", "http://127.0.0.1:8000/api/v1", "cookie-host"],
  ["INTERNAL_API_URL", "http://localhost:8000/api/v1", "internal-api"],
  ["SESSION_COOKIE_NAME", "other", "cookie-name"],
]) {
  test(`detects ${id} without leaking values`, () => {
    const checks = checkConfiguration({ ...env, [key]: value });
    assert.ok(errors(checks).some((item) => item.id === id));
    assert.ok(!JSON.stringify(checks).includes(env.POSTGRES_PASSWORD));
    assert.ok(!JSON.stringify(checks).includes(env.APP_SECRET_KEY));
  });
}

test("understands both Compose output formats and successful one-shot migrations", () => {
  const services = ["database", "api", "web"].map((Service) => ({ Service, State: "running", Health: "healthy" }));
  services.push({ Service: "migrations", State: "exited", ExitCode: 0 });
  assert.equal(errors(checkServices(services)).length, 0);
  assert.deepEqual(parseServices(JSON.stringify(services)), services);
  assert.deepEqual(parseServices(services.map((service) => JSON.stringify(service)).join("\n")), services);
  services[3].ExitCode = 1;
  assert.equal(errors(checkServices(services))[0].id, "service-migrations");
  assert.equal(errors(checkServices([])).length, 4);
});

test("missing env and docker produce actionable messages without external probes", async () => {
  const checks = await diagnose({ read: () => { throw new Error("sensitive/path"); }, run: () => ({ ok: false }), request: () => assert.fail("No requests without env") });
  assert.deepEqual(errors(checks).map((item) => item.id), ["env-file", "docker"]);
  assert.ok(!JSON.stringify(checks).includes("sensitive/path"));
});

test("refuses remote HTTP probes and URLs containing credentials", async () => {
  const request = () => assert.fail("Must not probe a remote or authenticated URL");
  assert.equal((await checkHttp({ ...env, APP_PUBLIC_URL: "https://example.com" }, request))[0].status, "warning");
  assert.equal((await checkHttp({ ...env, NEXT_PUBLIC_API_URL: "http://user:secret@localhost:8000/api/v1" }, request))[0].status, "error");
});

test("checks readiness, browser CORS and login without submitting credentials", async () => {
  const checks = await checkHttp(env, async (url, options) => {
    assert.equal(options.redirect, "error");
    assert.equal(options.body, undefined);
    if (String(url).endsWith("/health/ready")) return Response.json({ status: "ready", service: "neoguardian-insight-api" });
    if (options.method === "OPTIONS") return new Response(null, { headers: {
      "access-control-allow-origin": env.APP_PUBLIC_URL, "access-control-allow-credentials": "true",
      "access-control-allow-methods": "GET, POST, OPTIONS", "access-control-allow-headers": "Content-Type",
    } });
    return new Response("login");
  });
  assert.equal(errors(checks).length, 0);
});

test("reports database failure and CORS mismatch independently", async () => {
  const checks = await checkHttp(env, async (url) => String(url).endsWith("/health/ready")
    ? Response.json({ status: "not_ready", service: "neoguardian-insight-api", checks: { database: "unavailable" } }, { status: 503 })
    : new Response("ok"));
  assert.deepEqual(errors(checks).map((check) => check.id), ["api-ready", "cors-live"]);
});
