import { test } from "node:test";
import assert from "node:assert/strict";

process.env.SELLER_ADDRESS = "0x000000000000000000000000000000000000dEaD";
const { app } = await import("../src/server.ts");

test("invalid input is rejected before the payment step", async (t) => {
  const server = app.listen(0);
  t.after(() => server.close());
  const { port } = server.address() as { port: number };
  const res = await fetch(`http://localhost:${port}/npm-audit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ package: "../etc/passwd" }),
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("payment-required"), null);
});

test("OpenAPI spec is free and points at the public URL", async (t) => {
  const server = app.listen(0);
  t.after(() => server.close());
  const { port } = server.address() as { port: number };
  const res = await fetch(`http://localhost:${port}/openapi.json`);
  const spec = await res.json();
  assert.equal(res.status, 200);
  assert.equal(spec.openapi, "3.1.0");
  assert.equal(spec.servers[0].url, "https://api.sbu.dev");
  assert.ok(spec.paths["/npm-audit"].post);
});

const post = async (port: number, body: string) =>
  fetch(`http://localhost:${port}/npm-audit`, { method: "POST", headers: { "content-type": "application/json" }, body });

test("names, versions and bodies outside the npm rules are rejected before payment", async (t) => {
  const server = app.listen(0);
  t.after(() => server.close());
  const { port } = server.address() as { port: number };
  for (const body of [
    JSON.stringify({}),
    JSON.stringify({ package: 42 }),
    JSON.stringify({ package: "Express" }),
    JSON.stringify({ package: "a".repeat(215) }),
    JSON.stringify({ package: "express", version: "1.0.0 || 2" }),
    JSON.stringify({ package: "express", version: 5 }),
    JSON.stringify({ package: "express", version: "1".repeat(65) }),
  ]) {
    const res = await post(port, body);
    assert.equal(res.status, 400, body);
    assert.equal(res.headers.get("payment-required"), null, body);
  }
});

test("health is free and names the facilitator, and responses carry the sbu.dev header", async (t) => {
  const server = app.listen(0);
  t.after(() => server.close());
  const { port } = server.address() as { port: number };
  const res = await fetch(`http://localhost:${port}/health`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, facilitator: process.env.FACILITATOR_URL ?? "https://gateway-api-testnet.circle.com" });
  assert.equal(res.headers.get("x-powered-by"), "sbu.dev");
});
