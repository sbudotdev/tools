import { test } from "node:test";
import assert from "node:assert/strict";
import { audit, typosquatTargetOf, NotFound } from "../src/audit.ts";

const recent = new Date().toISOString();

function fakeFetch(registryDocument: object | null, vulns: object[] = []): typeof fetch {
  return (async (url: string) => {
    if (url.includes("osv.dev")) return Response.json({ vulns });
    return registryDocument ? Response.json(registryDocument) : new Response("", { status: 404 });
  }) as typeof fetch;
}

const registryDocumentFor = (name: string, version: string) => ({
  name,
  "dist-tags": { latest: version },
  versions: { [version]: { name, version } },
  time: { modified: recent },
});

test("healthy package scores 100", async () => {
  const verdict = await audit("express", undefined, fakeFetch(registryDocumentFor("express", "5.1.0")));
  assert.equal(verdict.version, "5.1.0");
  assert.equal(verdict.score, 100);
  assert.deepEqual(verdict.signals, []);
});

test("package with CVE loses points and links OSV", async () => {
  const fetchFn = fakeFetch(registryDocumentFor("lodash", "4.17.15"), [{ id: "GHSA-29mw-wpgm-hmr9", summary: "ReDoS" }]);
  const verdict = await audit("lodash", "4.17.15", fetchFn);
  assert.equal(verdict.score, 75);
  assert.equal(verdict.signals[0].kind, "cve");
  assert.equal(verdict.signals[0].source, "https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9");
});

test("typosquat is flagged", async () => {
  const verdict = await audit("lodahs", undefined, fakeFetch(registryDocumentFor("lodahs", "1.0.0")));
  assert.equal(verdict.signals[0].kind, "typosquat");
  assert.ok(verdict.score <= 40);
});

test("typosquat heuristic", () => {
  assert.equal(typosquatTargetOf("lodahs"), "lodash");
  assert.equal(typosquatTargetOf("expres"), "express");
  assert.equal(typosquatTargetOf("lodash"), undefined);
  assert.equal(typosquatTargetOf("left-pad"), undefined);
  assert.equal(typosquatTargetOf("totally-unrelated"), undefined);
});

test("missing package throws NotFound", async () => {
  await assert.rejects(audit("nope-nope", undefined, fakeFetch(null)), NotFound);
});

test("inherited object keys are not treated as versions", async () => {
  await assert.rejects(audit("express", "constructor", fakeFetch(registryDocumentFor("express", "5.1.0"))), NotFound);
});

test("OSV failure lowers confidence instead of failing", async () => {
  const fetchFn = (async (url: string) =>
    url.includes("osv.dev")
      ? new Response("", { status: 503 })
      : Response.json(registryDocumentFor("express", "5.1.0"))) as typeof fetch;
  const verdict = await audit("express", undefined, fetchFn);
  assert.equal(verdict.confidence, "low");
});

test("deprecated and stale packages lose points with the registry as source", async () => {
  const document = {
    ...registryDocumentFor("request", "2.88.2"),
    versions: { "2.88.2": { name: "request", version: "2.88.2", deprecated: "request has been deprecated" } },
    time: { modified: "2020-02-11T00:00:00.000Z" },
  };
  const verdict = await audit("request", undefined, fakeFetch(document));
  assert.deepEqual(verdict.signals.map((signal) => signal.kind), ["deprecated", "stale"]);
  assert.equal(verdict.signals[0].detail, "request has been deprecated");
  assert.equal(verdict.signals[1].detail, "no publish since 2020-02-11");
  assert.equal(verdict.signals[1].source, "https://registry.npmjs.org/request");
  assert.equal(verdict.score, 65);
});

test("a package without a modified time is not stale", async () => {
  const verdict = await audit("express", undefined, fakeFetch({ ...registryDocumentFor("express", "5.1.0"), time: {} }));
  assert.deepEqual(verdict.signals, []);
});

test("the score never goes below zero", async () => {
  const vulns = [1, 2, 3, 4, 5].map((n) => ({ id: `GHSA-${n}` }));
  const verdict = await audit("lodash", "4.17.15", fakeFetch(registryDocumentFor("lodash", "4.17.15"), vulns));
  assert.equal(verdict.signals.length, 5);
  assert.equal(verdict.signals[0].detail, "GHSA-1");
  assert.equal(verdict.score, 0);
});

test("a scoped name is fetched with its slash encoded", async () => {
  const urls: string[] = [];
  const fetchFn = (async (url: string) => {
    urls.push(url);
    return url.includes("osv.dev") ? Response.json({}) : Response.json(registryDocumentFor("@types/node", "22.0.0"));
  }) as typeof fetch;
  const verdict = await audit("@types/node", undefined, fetchFn);
  assert.equal(urls[0], "https://registry.npmjs.org/@types%2fnode");
  assert.equal(verdict.confidence, "high");
});

test("a registry error other than 404 is not NotFound", async () => {
  const fetchFn = (async () => new Response("", { status: 500 })) as typeof fetch;
  await assert.rejects(audit("express", undefined, fetchFn), (error) => !(error instanceof NotFound) && /registry responded 500/.test(String(error)));
});

test("an OSV request that throws lowers confidence instead of failing", async () => {
  const fetchFn = (async (url: string) => {
    if (url.includes("osv.dev")) throw new TypeError("fetch failed");
    return Response.json(registryDocumentFor("express", "5.1.0"));
  }) as typeof fetch;
  const verdict = await audit("express", undefined, fetchFn);
  assert.deepEqual([verdict.confidence, verdict.signals.length], ["low", 0]);
});
