// Runs against the compiled output: `pnpm test` builds first.
import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { doorkeepGate, lastForwardedFor } from "../dist/index.js";

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

function capture(status) {
  const seen = {};
  globalThis.fetch = async (url, init) => {
    seen.url = url;
    seen.headers = init.headers;
    return new Response("", { status });
  };
  return seen;
}

const req = (headers = {}) => new Request("https://shop.example/search?q=1", { headers });

test("forwards only the last X-Forwarded-For hop", async () => {
  const seen = capture(200);
  const r = await doorkeepGate(req({ "x-forwarded-for": "6.6.6.6, 203.0.113.9" }), { url: "http://dk:8080/" });
  assert.equal(r, null);
  assert.equal(seen.url, "http://dk:8080/v1/auth");
  assert.equal(seen.headers["X-Forwarded-For"], "203.0.113.9");
  assert.equal(seen.headers["X-Original-URI"], "/search?q=1");
  assert.equal(seen.headers["X-Forwarded-Host"], "shop.example");
});

test("clientIp overrides and can send no address", async () => {
  let seen = capture(200);
  await doorkeepGate(req({ "x-forwarded-for": "6.6.6.6" }), { url: "http://dk", clientIp: () => "198.51.100.4" });
  assert.equal(seen.headers["X-Forwarded-For"], "198.51.100.4");
  seen = capture(200);
  await doorkeepGate(req({ "x-forwarded-for": "6.6.6.6" }), { url: "http://dk", clientIp: () => undefined });
  assert.equal(seen.headers["X-Forwarded-For"], undefined);
});

test("browsers are redirected to the check, APIs get 401, deny is 403", async () => {
  capture(401);
  let r = await doorkeepGate(req({ accept: "text/html" }), { url: "http://dk" });
  assert.equal(r.status, 302);
  assert.equal(r.headers.get("location"), "https://shop.example/_dk/challenge?rd=%2Fsearch%3Fq%3D1");
  capture(401);
  r = await doorkeepGate(req({ accept: "application/json" }), { url: "http://dk" });
  assert.equal(r.status, 401);
  capture(403);
  r = await doorkeepGate(req(), { url: "http://dk" });
  assert.equal(r.status, 403);
});

test("fails open when doorkeep is unreachable", async () => {
  globalThis.fetch = async () => { throw new Error("ECONNREFUSED"); };
  assert.equal(await doorkeepGate(req(), { url: "http://dk" }), null);
});

test("the old string signature still works", async () => {
  const seen = capture(200);
  await doorkeepGate(req(), "http://legacy");
  assert.equal(seen.url, "http://legacy/v1/auth");
});

test("lastForwardedFor", () => {
  assert.equal(lastForwardedFor(req({ "x-forwarded-for": " a , b " })), "b");
  assert.equal(lastForwardedFor(req()), undefined);
});
