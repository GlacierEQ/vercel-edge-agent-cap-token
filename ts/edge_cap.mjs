import crypto from "node:crypto";

function digest(obj) {
  return crypto.createHash("sha256").update(JSON.stringify(obj, Object.keys(obj).sort().reduce((a,k)=>(a[k]=obj[k],a),{}))).digest("hex");
}

export function mint(secret, path, body, capabilities, notAfter) {
  const bodyDigest = digest(body);
  const caps = [...capabilities].sort();
  const raw = `${path}|${bodyDigest}|${caps.join("|")}|${notAfter}`;
  const mac = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  return { path, bodyDigest, capabilities: caps, notAfter, mac };
}

export function verify(secret, token, path, body, capability, now) {
  const bodyDigest = digest(body);
  const raw = `${token.path}|${token.bodyDigest}|${token.capabilities.join("|")}|${token.notAfter}`;
  const mac = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  if (mac !== token.mac) return { status: "REFUSE", reason: "BAD_MAC" };
  if (path !== token.path) return { status: "REFUSE", reason: "PATH_MISMATCH" };
  if (bodyDigest !== token.bodyDigest) return { status: "REFUSE", reason: "BODY_MISMATCH" };
  if (now > token.notAfter) return { status: "REFUSE", reason: "EXPIRED" };
  if (!token.capabilities.includes(capability)) return { status: "REFUSE", reason: "CAPABILITY_NOT_GRANTED" };
  return { status: "ALLOW", reason: null };
}
