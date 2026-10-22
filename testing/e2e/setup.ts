// Builds doorkeep, creates a site, starts doorkeep and the fixture site.
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
  const dkEnv = { ...env, DOORKEEP_DATA_DIR: data, DOORKEEP_LISTEN: `127.0.0.1:${DK_PORT}`, DOORKEEP_ADMIN_LISTEN: "public", DOORKEEP_LOG_LEVEL: "warn", DOORKEEP_IPDATA_AUTO_UPDATE: "false", DOORKEEP_TRUSTED_PROXIES: "127.0.0.1" };
  const out = execFileSync(join(ROOT, "bin/doorkeep"), ["site", "create", "--name", "e2e", "--origin", `http://localhost:${FIX_PORT}`], { env: dkEnv }).toString();
  const sitekey = /site key[^:]*:\s*(\S+)/.exec(out)![1];
  const secret = /secret[^:]*:\s*(\S+)/.exec(out)![1];

  execFileSync(join(ROOT, "bin/doorkeep"), ["admin", "create", "--user", "ops"], { env: dkEnv, input: "correct horse battery staple\n" });
  const nextOut = execFileSync(join(ROOT, "bin/doorkeep"), ["site", "create", "--name", "nextjs", "--origin", "http://localhost:18185"], { env: dkEnv }).toString();
  const nextKey = /site key[^:]*:\s*(\S+)/.exec(nextOut)![1];
  const nextSecret = /secret[^:]*:\s*(\S+)/.exec(nextOut)![1];
  // Sites behind the real nginx, Caddy and Traefik edge proxies (edge.spec.ts).
  for (const port of [18183, 18184, 18187]) {
    execFileSync(join(ROOT, "bin/doorkeep"), ["site", "create", "--name", `edge-${port}`, "--origin", `http://localhost:${port}`], { env: dkEnv });
  }

  const procs: ChildProcess[] = [];
  const groups: number[] = [];
  // Free ports a crashed previous run may still hold.
  for (const port of [DK_PORT, FIX_PORT, 18185]) {
    try { execFileSync("sh", ["-c", `for p in $(ss -ltnp "sport = :${port}" | grep -o 'pid=[0-9]*' | cut -d= -f2); do kill $p; done`], { stdio: "ignore" }); } catch {}
  }
  procs.push(spawn(join(ROOT, "bin/doorkeep"), ["serve"], { env: dkEnv, stdio: "inherit" }));
  await waitFor(`http://127.0.0.1:${DK_PORT}/healthz`);
  procs.push(spawn(process.execPath, [join(__dirname, "fixture/server.mjs")], {
    env: { ...env, DK_URL: `http://127.0.0.1:${DK_PORT}`, SITEKEY: sitekey, SECRET: secret, FIX_PORT: String(FIX_PORT) },
    stdio: "inherit",
  }));
  await waitFor(`http://127.0.0.1:${FIX_PORT}/`);
  process.env.DK_DATA = data;

  // The Next.js example (integrations/nextjs), built if needed.
  const nextDir = join(ROOT, "examples/nextjs-signup");
  const nextEnv = { ...env, DOORKEEP_URL: `http://127.0.0.1:${DK_PORT}`, DOORKEEP_SITE_KEY: nextKey, DOORKEEP_SECRET: nextSecret, PORT: "18185" };
  try {
    if (!existsSync(join(nextDir, ".next/BUILD_ID"))) execFileSync("npx", ["next", "build"], { cwd: nextDir, env: nextEnv, stdio: "ignore" });
    // Own process group so teardown also stops the next-server child.
    const nx = spawn("npx", ["next", "start", "-p", "18185", "-H", "127.0.0.1"], { cwd: nextDir, env: nextEnv, stdio: "ignore", detached: true });
    groups.push(nx.pid!);
    await waitFor("http://127.0.0.1:18185/", 60000);
    process.env.DK_NEXT = "1";
  } catch (e) {
    console.warn("Next.js example unavailable:", String(e).slice(0, 120));
  }

  // WordPress with the plugin (opt-in: DK_WP=1; pulls images, slow).
  let wp = false;
  if (process.env.DK_WP === "1") {
    try {
      const o = execFileSync(join(ROOT, "bin/doorkeep"), ["site", "create", "--name", "wordpress", "--origin", "http://localhost:18186"], { env: dkEnv }).toString();
      const k = /site key[^:]*:\s*(\S+)/.exec(o)![1], sec = /secret[^:]*:\s*(\S+)/.exec(o)![1];
      execFileSync(join(ROOT, "testing/wordpress/up.sh"), [k, sec], { stdio: "inherit" });
      process.env.DK_WP_READY = "1";
      const wc = join(ROOT, "testing/wordpress/.wc");
      if (existsSync(wc)) process.env.DK_WC_READY = readFileSync(wc, "utf8").trim(); // "<product id> <checkout page id>"
      wp = true;
    } catch (e) {
      console.warn("WordPress unavailable:", String(e).slice(0, 160));
    }
  }

  // Real nginx and Caddy in front of doorkeep, if Docker is available.
  const edge = join(__dirname, "edge");
  const containers: string[] = [];
  try {
    execFileSync("docker", ["rm", "-f", "dk-e2e-nginx", "dk-e2e-caddy", "dk-e2e-traefik"], { stdio: "ignore" });
  } catch {}
  try {
    execFileSync("docker", ["run", "-d", "--name", "dk-e2e-nginx", "--network", "host",
      "-v", `${edge}/nginx.conf:/etc/nginx/nginx.conf:ro`, "-v", `${ROOT}/integrations/nginx/doorkeep.conf:/etc/nginx/doorkeep.conf:ro`,
      "-v", `${edge}/www:/srv:ro`, "nginx:1.27-alpine"], { stdio: "ignore" });
    containers.push("dk-e2e-nginx");
    execFileSync("docker", ["run", "-d", "--name", "dk-e2e-caddy", "--network", "host",
      "-v", `${edge}/Caddyfile:/etc/caddy/Caddyfile:ro`, "-v", `${edge}/www:/srv:ro`, "caddy:2-alpine"], { stdio: "ignore" });
    containers.push("dk-e2e-caddy");
    // Traefik runs the shipped integration file with only the upstream
    // addresses swapped, so the test covers what users copy.
    const traefikCfg = join(data, "traefik-dynamic.yml");
    writeFileSync(traefikCfg, readFileSync(join(ROOT, "integrations/traefik/dynamic.yml"), "utf8")
      .replaceAll("http://doorkeep:8080", `http://127.0.0.1:${DK_PORT}`)
      .replaceAll("http://app:3000", "http://127.0.0.1:18188"));
    execFileSync("docker", ["run", "-d", "--name", "dk-e2e-traefik", "--network", "host",
      "-v", `${traefikCfg}:/etc/traefik/dynamic.yml:ro`, "traefik:v3.3",
      "--entrypoints.web.address=:18187", "--providers.file.filename=/etc/traefik/dynamic.yml"], { stdio: "ignore" });
    containers.push("dk-e2e-traefik");
    await waitFor("http://127.0.0.1:18183/_dk/healthz");
    await waitFor("http://127.0.0.1:18184/_dk/healthz");
    await waitFor("http://127.0.0.1:18187/_dk/healthz");
    process.env.DK_EDGE = "1";
  } catch (e) {
    console.warn("edge proxies unavailable, edge tests will be skipped:", String(e).slice(0, 120));
  }

  return async () => {
    if (wp) {
      try { execFileSync(join(ROOT, "testing/wordpress/down.sh"), { stdio: "ignore" }); } catch {}
    }
    for (const c of containers) {
      try { execFileSync("docker", ["rm", "-f", c], { stdio: "ignore" }); } catch {}
    }
    for (const g of groups) {
      try { process.kill(-g, "SIGTERM"); } catch {}
    }
    procs.forEach((p) => p.kill("SIGTERM"));
    rmSync(data, { recursive: true, force: true });
  };
}
