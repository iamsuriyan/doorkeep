// Builds the dashboard into ../../internal/api/assets/admin, which the Go
// binary embeds and serves at /admin/.
import { build } from "esbuild";
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";

const out = "../../internal/api/assets/admin";
mkdirSync(out, { recursive: true });
await build({
  entryPoints: ["src/main.tsx"], bundle: true, minify: true, target: "es2020", format: "esm",
  jsx: "automatic", jsxImportSource: "preact", outfile: out + "/app.js", legalComments: "none",
});
copyFileSync("src/app.css", out + "/app.css");
copyFileSync("src/index.html", out + "/index.html");
const js = readFileSync(out + "/app.js");
console.log(`dashboard app.js ${js.length} B, ${gzipSync(js).length} B gzip`);
