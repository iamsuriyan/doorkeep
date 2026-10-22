// Builds doorkeep, creates a site, starts doorkeep and the fixture site.
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const ROOT = resolve(__dirname, "../..");
const DK_PORT = 18181;
const FIX_PORT = 18182;

async function waitFor(url: string, ms = 15000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      if ((await fetch(url)).status < 500) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("timeout waiting for " + url);
}

export default async function setup() {
  const env = { ...process.env, PATH: `${process.env.HOME}/.local/go/bin:${process.env.PATH}` };
  execFileSync("go", ["build", "-o", join(ROOT, "bin/doorkeep"), "./cmd/doorkeep"], { cwd: ROOT, env, stdio: "inherit" });
  const data = mkdtempSync(join(tmpdir(), "dk-e2e-"));
  const dkEnv = { ...env, DOORKEEP_DATA_DIR: data, DOORKEEP_LISTEN: `127.0.0.1:${DK_PORT}`, DOORKEEP_LOG_LEVEL: "warn", DOORKEEP_IPDATA_AUTO_UPDATE: "false", DOORKEEP_TRUSTED_PROXIES: "127.0.0.1" };
  const out = execFileSync(join(ROOT, "bin/doorkeep"), ["site", "create", "--name", "e2e", "--origin", `http://localhost:${FIX_PORT}`], { env: dkEnv }).toString();
  const sitekey = /site key[^:]*:\s*(\S+)/.exec(out)![1];
  const secret = /secret[^:]*:\s*(\S+)/.exec(out)![1];

  execFileSync(join(ROOT, "bin/doorkeep"), ["admin", "create", "--user", "ops"], { env: dkEnv, input: "correct horse battery staple\n" });
  // Sites behind the real nginx and Caddy edge proxies (edge.spec.ts).
  for (const port of [18183, 18184]) {
    execFileSync(join(ROOT, "bin/doorkeep"), ["site", "create", "--name", `edge-${port}`, "--origin", `http://localhost:${port}`], { env: dkEnv });
  }

  const procs: ChildProcess[] = [];
  procs.push(spawn(join(ROOT, "bin/doorkeep"), ["serve"], { env: dkEnv, stdio: "inherit" }));
  await waitFor(`http://127.0.0.1:${DK_PORT}/healthz`);
  procs.push(spawn(process.execPath, [join(__dirname, "fixture/server.mjs")], {
    env: { ...env, DK_URL: `http://127.0.0.1:${DK_PORT}`, SITEKEY: sitekey, SECRET: secret, FIX_PORT: String(FIX_PORT) },
    stdio: "inherit",
  }));
  await waitFor(`http://127.0.0.1:${FIX_PORT}/`);
  process.env.DK_DATA = data;

  // Real nginx and Caddy in front of doorkeep, if Docker is available.
  const edge = join(__dirname, "edge");
  const containers: string[] = [];
  try {
    execFileSync("docker", ["rm", "-f", "dk-e2e-nginx", "dk-e2e-caddy"], { stdio: "ignore" });
  } catch {}
  try {
    execFileSync("docker", ["run", "-d", "--name", "dk-e2e-nginx", "--network", "host",
      "-v", `${edge}/nginx.conf:/etc/nginx/nginx.conf:ro`, "-v", `${ROOT}/integrations/nginx/doorkeep.conf:/etc/nginx/doorkeep.conf:ro`,
      "-v", `${edge}/www:/srv:ro`, "nginx:1.27-alpine"], { stdio: "ignore" });
    containers.push("dk-e2e-nginx");
    execFileSync("docker", ["run", "-d", "--name", "dk-e2e-caddy", "--network", "host",
      "-v", `${edge}/Caddyfile:/etc/caddy/Caddyfile:ro`, "-v", `${edge}/www:/srv:ro`, "caddy:2-alpine"], { stdio: "ignore" });
    containers.push("dk-e2e-caddy");
    await waitFor("http://127.0.0.1:18183/_dk/healthz");
    await waitFor("http://127.0.0.1:18184/_dk/healthz");
    process.env.DK_EDGE = "1";
  } catch (e) {
    console.warn("edge proxies unavailable, edge tests will be skipped:", String(e).slice(0, 120));
  }

  return async () => {
    for (const c of containers) {
      try { execFileSync("docker", ["rm", "-f", c], { stdio: "ignore" }); } catch {}
    }
    procs.forEach((p) => p.kill("SIGTERM"));
    rmSync(data, { recursive: true, force: true });
  };
}
