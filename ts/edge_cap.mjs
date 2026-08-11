import crypto from "node:crypto";

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const MAX_PATH_LEN = 2048;
const MAX_CAP_LEN = 256;
const TOKEN_VERSION = "edge-cap-v1";

function f64Hex(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new TypeError("time values must be finite numbers");
  const buf = Buffer.allocUnsafe(8);
  buf.writeDoubleBE(value, 0);
  return buf.toString("hex");
}

function validateAsciiField(value, name, maxLen) {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLen) throw new TypeError(`${name} must be a non-empty bounded string`);
  for (const ch of value) {
    const code = ch.codePointAt(0);
    if (code < 0x20 || code > 0x7e) throw new TypeError(`${name} must contain printable ASCII only`);
  }
  return value;
}

function validatePath(path) {
  validateAsciiField(path, "path", MAX_PATH_LEN);
  if (!path.startsWith("/")) throw new TypeError("path must be absolute");
  return path;
}

function validateCapability(capability) {
  return validateAsciiField(capability, "capability", MAX_CAP_LEN);
}

function normalizeCapabilities(capabilities) {
  if (!Array.isArray(capabilities) && !(capabilities instanceof Set)) throw new TypeError("capabilities must be an array or set");
  const values = [...capabilities].map(validateCapability);
  if (values.length === 0) throw new TypeError("at least one capability is required");
  if (new Set(values).size !== values.length) throw new TypeError("duplicate capabilities are not canonical");
  return values.sort();
}

function canonicalBody(value) {
  if (value === null) return ["null"];
  if (typeof value === "boolean") return ["bool", value];
  if (typeof value === "string") return ["str", value];
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("body contains non-finite number");
    if (Number.isSafeInteger(value)) return ["num", String(value)];
    return ["f64", f64Hex(value)];
  }
  if (Array.isArray(value)) return ["arr", value.map(canonicalBody)];
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new TypeError("body object must be plain");
    const keys = Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")));
    return ["obj", keys.map((key) => [key, canonicalBody(value[key])])];
  }
  throw new TypeError(`unsupported body value: ${typeof value}`);
}

export function canonicalBodyBytes(obj) {
  return Buffer.from(JSON.stringify(canonicalBody(obj)), "utf8");
}

export function digest(obj) {
  return crypto.createHash("sha256").update(canonicalBodyBytes(obj)).digest("hex");
}

function signingPayload(path, bodyDigest, capabilities, notAfter) {
  return Buffer.from(JSON.stringify([TOKEN_VERSION, path, bodyDigest, capabilities, f64Hex(notAfter)]), "utf8");
}

function validateSecret(secret) {
  if ((typeof secret !== "string" && !Buffer.isBuffer(secret)) || secret.length === 0) throw new TypeError("secret must be non-empty");
  return secret;
}

export function mint(secret, path, body, capabilities, notAfter) {
  validateSecret(secret);
  const canonicalPath = validatePath(path);
  const caps = normalizeCapabilities(capabilities);
  f64Hex(notAfter);
  const bodyDigest = digest(body);
  const raw = signingPayload(canonicalPath, bodyDigest, caps, notAfter);
  const mac = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  return { path: canonicalPath, bodyDigest, capabilities: caps, notAfter, mac };
}

export function verify(secret, token, path, body, capability, now) {
  try {
    validateSecret(secret);
    const requestPath = validatePath(path);
    const requestCapability = validateCapability(capability);
    f64Hex(now);
    if (!token || typeof token !== "object" || Array.isArray(token)) throw new TypeError("invalid token");
    const tokenPath = validatePath(token.path);
    const tokenCaps = normalizeCapabilities(token.capabilities);
    f64Hex(token.notAfter);
    if (typeof token.bodyDigest !== "string" || !/^[0-9a-f]{64}$/.test(token.bodyDigest)) throw new TypeError("invalid body digest");
    if (typeof token.mac !== "string" || !/^[0-9a-f]{64}$/.test(token.mac)) throw new TypeError("invalid mac");

    const bodyDigest = digest(body);
    const raw = signingPayload(tokenPath, token.bodyDigest, tokenCaps, token.notAfter);
    const expected = crypto.createHmac("sha256", secret).update(raw).digest();
    const supplied = Buffer.from(token.mac, "hex");
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(expected, supplied)) return { status: "REFUSE", reason: "BAD_MAC" };
    if (requestPath !== tokenPath) return { status: "REFUSE", reason: "PATH_MISMATCH" };
    if (bodyDigest !== token.bodyDigest) return { status: "REFUSE", reason: "BODY_MISMATCH" };
    if (now > token.notAfter) return { status: "REFUSE", reason: "EXPIRED" };
    if (!tokenCaps.includes(requestCapability)) return { status: "REFUSE", reason: "CAPABILITY_NOT_GRANTED" };
    return { status: "ALLOW", reason: null };
  } catch (error) {
    if (error instanceof TypeError || error instanceof RangeError) return { status: "REFUSE", reason: "MALFORMED_REQUEST_OR_TOKEN" };
    throw error;
  }
}
