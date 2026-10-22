// Fixture "customer site" for e2e tests. Mirrors a real deployment:
//  - serves a signup form that includes the doorkeep snippet
//  - proxies /_dk/* to doorkeep on the same origin (recommended setup)
//  - its backend verifies the token with /v1/siteverify using the secret
import http from "node:http";

const { DK_URL, SITEKEY, SECRET, FIX_PORT } = process.env;
const results = new Map();

function page(url) {
  const run = url.searchParams.get("run") || "default";
  const auto = Number(url.searchParams.get("auto") || 0);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Signup</title>
<script src="/_dk/v1/dk.js" data-sitekey="${SITEKEY}" async defer></script></head>
<body><main><h1>Create account</h1>
<form id="f" method="POST" action="/signup">
  <input type="hidden" name="run" value="${run}">
  <label>Name <input name="name" id="name" autocomplete="name"></label>
  <label>Email <input name="email" id="email" type="email" autocomplete="email"></label>
  <div class="doorkeep" data-action="signup"></div>
  <button id="go" type="submit">Sign up</button>
</form></main>
${auto ? `<script>setTimeout(function(){document.getElementById("f").requestSubmit()}, ${auto})</script>` : ""}
</body></html>`;
}

function proxy(req, res) {
  const target = new URL(DK_URL + req.url.replace(/^\/_dk/, ""));
  const headers = { ...req.headers, host: target.host };
  const up = http.request(target, { method: req.method, headers }, (r) => {
    res.writeHead(r.statusCode, r.headers);
    r.pipe(res);
  });
  up.on("error", () => { res.writeHead(502); res.end(); });
  req.pipe(up);
}

async function readBody(req) {
  let b = "";
  for await (const c of req) b += c;
  return b;
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname.startsWith("/_dk/")) return proxy(req, res);
  if (req.method === "GET" && url.pathname === "/") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(page(url));
  }
  if (req.method === "POST" && url.pathname === "/signup") {
    const form = new URLSearchParams(await readBody(req));
    const vr = await fetch(DK_URL + "/v1/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret: SECRET, response: form.get("dk-response") || "", expected_action: "signup" }),
    }).then((r) => r.json());
    results.set(form.get("run"), vr);
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(`<!doctype html><pre id="result">${JSON.stringify(vr).replace(/</g, "&lt;")}</pre>`);
  }
  if (req.method === "GET" && url.pathname === "/ui-harness") {
    // Opens the challenge dialog directly with placeholder media, for
    // accessibility and keyboard tests.
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>UI harness</title></head><body>
<button id="opener">Open</button>
<script src="/_dk/v1/dk-ui.js"></script>
<script>
  window.result = null;
  document.getElementById("opener").onclick = () => window.__doorkeepUI.open({
    image: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='260' height='90'/%3E",
    audio: "", audioSlow: "", length: 5, attemptsLeft: 3, accessibilityUrl: "https://example.com/help",
    submit: async (a) => a.toUpperCase() === "ACDEF" ? { ok: true, token: "tok" } : { ok: false, attemptsLeft: 2 },
  }).then(t => window.result = "token:" + t, e => window.result = "error:" + e.message);
</script></body></html>`);
  }
  if (url.pathname === "/result") {
    const r = results.get(url.searchParams.get("run"));
    res.writeHead(r ? 200 : 404, { "Content-Type": "application/json" });
    return res.end(JSON.stringify(r || null));
  }
  res.writeHead(404);
  res.end();
}).listen(Number(FIX_PORT), "127.0.0.1");
