// 用本机 magpie 已保存的 CodeArts 账号，诊断 inferhub 的鉴权方式。
// 只发一条 max_tokens=1 的探测请求，不打印任何凭据值。
// usage: node diagnose-inferhub.mjs [authFile]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { _internal } from "../index.mjs";

const { signRequest, INFERHUB_BASE } = _internal;

const authFile = process.argv[2] ?? path.join(os.homedir(), ".config", "magpie", "plugin-auth.json");
const raw = JSON.parse(fs.readFileSync(authFile, "utf8"));
const entry = raw.codearts;
const auth = Array.isArray(entry) ? entry[0] : entry;
if (!auth) throw new Error("plugin-auth.json 里没有 codearts 账号");

const expires = Number(auth.expires);
console.log("expires 原值        :", auth.expires);
console.log("expires 作为毫秒    :", new Date(expires).toISOString());
console.log("距现在              :", ((expires - Date.now()) / 60000).toFixed(1), "分钟");
console.log("作为秒解释          :", new Date(expires * 1000).toISOString());
console.log("accessKey 长度      :", auth.accessKey?.length, " securityToken 长度:", auth.securityToken?.length);
console.log("securityToken 前缀  :", String(auth.securityToken).slice(0, 12), "…");
console.log("refresh 前缀        :", String(auth.refresh).slice(0, 12), "…");

const url = `${INFERHUB_BASE}chat/completions`;
const body = JSON.stringify({
  model: "GLM-5.1",
  messages: [{ role: "user", content: "ping" }],
  max_tokens: 1,
  stream: false,
});

const attempt = async (label, headersFactory) => {
  const headers = new Headers({ "content-type": "application/json" });
  const signed = headersFactory(headers) ?? {};
  for (const [key, value] of Object.entries(signed)) headers.set(key, String(value));
  try {
    const res = await fetch(url, { method: "POST", headers, body });
    const text = (await res.text()).slice(0, 260).replace(/\s+/g, " ");
    console.log(`\n[${label}] -> ${res.status}`);
    console.log(`   ${text}`);
    return res.status;
  } catch (error) {
    console.log(`\n[${label}] -> ERROR ${error.message}`);
    return 0;
  }
};

const whitelist = (extra = {}) => (headers) => {
  const mine = {};
  for (const [key, value] of headers.entries()) mine[key] = value;
  return signRequest(
    { method: "POST", url, headers: { ...mine, "x-security-token": auth.securityToken, ...extra }, body },
    auth.accessKey,
    auth.secretKey,
  );
};

// 1) 当前插件实现：把调用方给的所有头都纳入签名
await attempt("A 全量头签名（当前实现）", (headers) => {
  const mine = { "x-security-token": auth.securityToken, "content-type": "application/json" };
  return signRequest({ method: "POST", url, headers: mine, body }, auth.accessKey, auth.secretKey);
});

// 2) 白名单头签名
await attempt("B 白名单头签名", whitelist());

// 3) 白名单 + maas_type
await attempt("C 白名单签名 + maas_type=benefit", whitelist({ maas_type: "benefit" }));

// 4) 只带 x-auth-token = securityToken
await attempt("D x-auth-token = securityToken", () => ({
  "x-auth-token": auth.securityToken,
}));

// 5) 只带 x-auth-token = access
await attempt("E x-auth-token = access", () => ({ "x-auth-token": auth.access }));

// 6) Bearer securityToken
await attempt("F Bearer securityToken", () => ({ authorization: `Bearer ${auth.securityToken}` }));

process.exit(0);
