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
  const dkEnv = { ...env, DOORKEEP_DATA_DIR: data, DOORKEEP_LISTEN: `127.0.0.1:${DK_PORT}`, DOORKEEP_LOG_LEVEL: "warn", DOORKEEP_IPDATA_AUTO_UPDATE: "false" };
  const out = execFileSync(join(ROOT, "bin/doorkeep"), ["site", "create", "--name", "e2e", "--origin", `http://localhost:${FIX_PORT}`], { env: dkEnv }).toString();
  const sitekey = /site key[^:]*:\s*(\S+)/.exec(out)![1];
  const secret = /secret[^:]*:\s*(\S+)/.exec(out)![1];

  const procs: ChildProcess[] = [];
  procs.push(spawn(join(ROOT, "bin/doorkeep"), ["serve"], { env: dkEnv, stdio: "inherit" }));
  await waitFor(`http://127.0.0.1:${DK_PORT}/healthz`);
  procs.push(spawn(process.execPath, [join(__dirname, "fixture/server.mjs")], {
    env: { ...env, DK_URL: `http://127.0.0.1:${DK_PORT}`, SITEKEY: sitekey, SECRET: secret, FIX_PORT: String(FIX_PORT) },
    stdio: "inherit",
  }));
  await waitFor(`http://127.0.0.1:${FIX_PORT}/`);
  process.env.DK_DATA = data;

  return async () => {
    procs.forEach((p) => p.kill("SIGTERM"));
    rmSync(data, { recursive: true, force: true });
  };
}
