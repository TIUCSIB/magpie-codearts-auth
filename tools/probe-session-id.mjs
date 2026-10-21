// 对照实验：在可能已满额的情况下，看哪种会话标识能让请求被算作同一个会话。
// 每个组合只发一次 max_tokens=1 的请求；不打印凭据。
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { _internal } from "../index.mjs";

const { INFERHUB_BASE, signRequest } = _internal;
const authFile = process.argv[2] ?? path.join(os.homedir(), ".config", "magpie", "plugin-auth.json");
const entry = JSON.parse(fs.readFileSync(authFile, "utf8")).codearts;
const auth = Array.isArray(entry) ? entry[0] : entry;

const STABLE_ID = "codearts-agent-magpie-fixed";

const attempt = async (label, { headers: extraHeaders = {}, query = "", bodyExtra = {} } = {}) => {
  const url = `${INFERHUB_BASE}chat/completions${query}`;
  const body = JSON.stringify({
    model: "GLM-5.1",
    messages: [{ role: "user", content: "ping" }],
    max_tokens: 1,
    stream: false,
    ...bodyExtra,
  });
  const headers = {
    "content-type": "application/json",
    "x-security-token": auth.securityToken,
    "x-language": "zh-cn",
    "x-ot-client-type": "CodeArts",
    "x-ot-client-version": "0.2.6",
    ...extraHeaders,
  };
  const signed = signRequest({ method: "POST", url, headers, body }, auth.accessKey, auth.secretKey);
  const outgoing = new Headers();
  for (const [key, value] of Object.entries(signed)) {
    if (key.toLowerCase() !== "host") outgoing.set(key, String(value));
  }
  const res = await fetch(url, { method: "POST", headers: outgoing, body });
  const text = await res.text();
  const limited = text.includes("TM.00001041");
  console.log(
    `[${label}] -> ${res.status}${limited ? " 并发上限" : res.status === 200 ? " 成功" : ""}${
      limited || res.status === 200 ? "" : `  ${text.slice(0, 120).replace(/\s+/g, " ")}`
    }`,
  );
  return { status: res.status, limited, text };
};

console.log("固定标识:", STABLE_ID, "\n");
await attempt("a 基线（无会话标识）");
await attempt("b x-snap-client-id", { headers: { "x-snap-client-id": STABLE_ID } });
await attempt("c x-ot-client-id", { headers: { "x-ot-client-id": STABLE_ID } });
await attempt("d query clientId", { query: `?clientId=${encodeURIComponent(STABLE_ID)}` });
await attempt("e header clientId", { headers: { clientId: STABLE_ID } });
await attempt("f header x-client-id", { headers: { "x-client-id": STABLE_ID } });
await attempt("g body client_id", { bodyExtra: { client_id: STABLE_ID } });
await attempt("h body session_id", { bodyExtra: { session_id: STABLE_ID } });
process.exit(0);
