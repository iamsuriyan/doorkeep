// Builds the PoW worker to a string, inlines it into the snippet, emits an
// IIFE for <script> use and an ESM build for bundlers, then copies the IIFE
// into the Go server's embedded assets.
import { build } from "esbuild";
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";

const worker = await build({
  entryPoints: ["src/pow.worker.ts"],
  bundle: true, minify: true, write: false, format: "iife", target: "es2020",
});
const workerCode = worker.outputFiles[0].text;

const common = {
  entryPoints: ["src/index.ts"],
  bundle: true, minify: true, target: "es2020",
  define: { __POW_WORKER__: JSON.stringify(workerCode), __DK_VERSION__: "1" },
  legalComments: "none",
};
mkdirSync("dist", { recursive: true });
await build({ ...common, format: "iife", outfile: "dist/dk.js" });
await build({ ...common, format: "esm", outfile: "dist/dk.esm.js" });

copyFileSync("dist/dk.js", "../../internal/api/assets/dk.js");
const gz = gzipSync(readFileSync("dist/dk.js")).length;
console.log(`dk.js ${readFileSync("dist/dk.js").length} B, ${gz} B gzip`);
if (gz > 14336) { console.error("snippet exceeds 14 KB gzip budget"); process.exit(1); }
