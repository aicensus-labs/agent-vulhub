"use strict";
// Adapter, not upstream code: n8n signs and verifies its OAuth tokens with the
// `jsonwebtoken` package. This implements the same HS256 signing, signature
// check, audience check and expiry check over node:crypto so the lab needs no
// package installation. The upstream JwtService drives it unchanged.
const crypto = require("node:crypto");
const base64url = (value) => Buffer.from(value).toString("base64url");
const decodeSegment = (value) => JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
const audienceMatches = (claim, expected) => {
  const list = Array.isArray(claim) ? claim : [claim];
  const wanted = Array.isArray(expected) ? expected : [expected];
  return list.some((item) => wanted.includes(item));
};
const sign = (payload, secret, options = {}) => {
  const header = { alg: "HS256", typ: "JWT" };
  let body = { ...payload };
  if (options.expiresIn) {
    const seconds = typeof options.expiresIn === "number"
      ? options.expiresIn
      : ({ "10m": 600, "1h": 3600 }[options.expiresIn] || 600);
    const now = Math.floor(Date.now() / 1000);
    body = { ...body, iat: now, exp: now + seconds };
  }
  const encoded = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(body));
  const signature = crypto.createHmac("sha256", secret).update(encoded).digest("base64url");
  return encoded + "." + signature;
};
const verify = (token, secret, options = {}) => {
  if (typeof secret !== "string" || !secret) throw new Error("secret or public key must be provided");
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("jwt malformed");
  const [header, payload, signature] = parts;
  if (decodeSegment(header).alg !== "HS256") throw new Error("invalid algorithm");
  const expected = crypto.createHmac("sha256", secret).update(header + "." + payload).digest("base64url");
  const left = Buffer.from(signature);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) throw new Error("invalid signature");
  const claims = decodeSegment(payload);
  if (typeof claims.exp === "number" && claims.exp < Math.floor(Date.now() / 1000)) throw new Error("jwt expired");
  if (options.audience !== undefined && !audienceMatches(claims.aud, options.audience)) throw new Error("jwt audience invalid");
  if (options.issuer !== undefined && !audienceMatches(claims.iss, options.issuer)) throw new Error("jwt issuer invalid");
  return claims;
};
const decode = (token) => {
  const parts = String(token).split(".");
  if (parts.length < 2) return null;
  try { return decodeSegment(parts[1]); } catch { return null; }
};
exports.sign = sign;
exports.verify = verify;
exports.decode = decode;
