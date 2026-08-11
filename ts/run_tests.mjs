import { digest, mint, verify } from "./edge_cap.mjs";
import assert from "node:assert/strict";

const secret = "v-secret";
const body = { q: 1 };
const tok = mint(secret, "/api/agent", body, ["llm:complete"], 1000);
assert.deepEqual(verify(secret, tok, "/api/agent", body, "llm:complete", 900), { status: "ALLOW", reason: null });
assert.equal(verify(secret, tok, "/api/agent", { q: 2 }, "llm:complete", 900).reason, "BODY_MISMATCH");
assert.equal(verify(secret, tok, "/api/agent", body, "llm:complete", 1000.01).reason, "EXPIRED");

const nested = { q: 1, nested: { b: 2, a: [true, null, 1.5] }, z: "ok" };
const reordered = { z: "ok", nested: { a: [true, null, 1.5], b: 2 }, q: 1 };
const expectedDigest = "c6b19cf225ceae830a0dc80a6e6dc5774f7ddac7be39ba7f4bf3f5755bbcf848";
const expectedMac = "7bd5c4fa9c2442da76bfbed9721a501faedfa8b466c59ba517ea98d7c86b4762";
assert.equal(digest(nested), expectedDigest);
assert.equal(digest(reordered), expectedDigest);
assert.notEqual(digest({ q: 1, nested: { b: 3, a: [true, null, 1.5] }, z: "ok" }), expectedDigest);
const vector = mint(secret, "/api/agent", nested, ["tool:read", "llm:complete"], 1000);
assert.equal(vector.bodyDigest, expectedDigest);
assert.equal(vector.mac, expectedMac);
assert.equal(verify(secret, vector, "/api/agent", nested, "tool:read", 999).status, "ALLOW");

const delimiter = mint(secret, "/api/agent", body, ["a|b", "c"], 1000);
const structurallyDifferent = { ...delimiter, capabilities: ["a", "b|c"] };
assert.equal(verify(secret, structurallyDifferent, "/api/agent", body, "a", 900).reason, "BAD_MAC");

for (const bad of [
  () => mint("", "/api/agent", body, ["llm:complete"], 1000),
  () => mint(secret, "", body, ["llm:complete"], 1000),
  () => mint(secret, "relative", body, ["llm:complete"], 1000),
  () => mint(secret, "/api/agent", body, [], 1000),
  () => mint(secret, "/api/agent", body, [""], 1000),
  () => mint(secret, "/api/agent", body, ["llm:complete"], Number.NaN),
  () => digest({ bad: Number.POSITIVE_INFINITY }),
]) assert.throws(bad);

assert.equal(verify(secret, tok, "/api/agent", body, "llm:complete", Number.NaN).reason, "MALFORMED_REQUEST_OR_TOKEN");
assert.equal(verify(secret, { ...tok, mac: "zz" }, "/api/agent", body, "llm:complete", 900).reason, "MALFORMED_REQUEST_OR_TOKEN");

console.log("ok");
