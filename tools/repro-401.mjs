// 复现 401：模拟 magpie 实际转发时带的头（含 authorization），对比「全量头签名」与「白名单签名」。
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { _internal } from "../index.mjs";

const { signRequest, INFERHUB_BASE } = _internal;
const authFile = process.argv[2] ?? path.join(os.homedir(), ".config", "magpie", "plugin-auth.json");
const entry = JSON.parse(fs.readFileSync(authFile, "utf8")).codearts;
const auth = Array.isArray(entry) ? entry[0] : entry;

const url = `${INFERHUB_BASE}chat/completions`;
const body = JSON.stringify({
  model: "GLM-5.1",
  messages: [{ role: "user", content: "ping" }],
  max_tokens: 1,
  stream: false,
});

// magpie / AI SDK 实际会带上的头
const incoming = {
  "content-type": "application/json",
  authorization: "Bearer ",
  accept: "*/*",
  "user-agent": "Bun/1.4.3",
  "accept-encoding": "gzip, deflate",
  "x-ot-client-type": "opencode-codearts-auth",
  "x-ot-client-version": "0.1.0",
};

const run = async (label, build) => {
  const headers = build(incoming);
  const signed = signRequest({ method: "POST", url, headers, body }, auth.accessKey, auth.secretKey);
  const outgoing = new Headers(incoming);
  for (const [key, value] of Object.entries(signed)) {
    if (key.toLowerCase() === "host") continue;
    outgoing.set(key, String(value));
  }
  // 复现旧实现：authorization 先参与签名，再被签名值覆盖
  const res = await fetch(url, { method: "POST", headers: outgoing, body });
  const text = (await res.text()).slice(0, 200).replace(/\s+/g, " ");
  console.log(`[${label}] -> ${res.status}  ${text}`);
  const signedList = String(outgoing.get("authorization")).match(/SignedHeaders=([^,]+)/)?.[1];
  console.log(`   实际发出 SignedHeaders: ${signedList}`);
  console.log(`   实际发出有没有 authorization 之外的差异头: accept=${outgoing.get("accept")} accept-encoding=${outgoing.get("accept-encoding")}`);
  return res.status;
};

// 旧实现：调用方给的所有头都进签名
const oldWay = { ...incoming, "x-security-token": auth.securityToken };
await run("旧：全量头签名", () => oldWay);

// 新实现：白名单头签名
await run("新：白名单签名", () => {
  const whitelist = ["content-type", "x-security-token", "x-language", "plugin-name", "plugin-version", "x-ot-client-type", "x-ot-client-version"];
  const headers = { "x-security-token": auth.securityToken, "x-language": "zh-cn" };
  for (const name of whitelist) {
    const value = name === "x-security-token" ? auth.securityToken : incoming[name];
    if (value !== undefined) headers[name] = value;
  }
  return headers;
});

process.exit(0);
