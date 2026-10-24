// 测「流式请求是否会漏掉会话名额」：先完整读一条 stream 响应，再打一条普通请求看是否被并发上限挡住。
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { _internal } from "../index.mjs";

const { INFERHUB_BASE, signRequest } = _internal;
const authFile = process.argv[2] ?? path.join(os.homedir(), ".config", "magpie", "plugin-auth.json");
const entry = JSON.parse(fs.readFileSync(authFile, "utf8")).codearts;
const auth = Array.isArray(entry) ? entry[0] : entry;

const send = async (label, body) => {
  const url = `${INFERHUB_BASE}chat/completions`;
  const headers = {
    "content-type": "application/json",
    "x-security-token": auth.securityToken,
    "x-language": "zh-cn",
    "x-ot-client-type": "magpie-codearts-auth",
    "x-ot-client-version": "0.1.0",
    "plugin-name": "snap_AIIDE",
    "plugin-version": "5.1.0",
  };
  const signed = signRequest({ method: "POST", url, headers, body }, auth.accessKey, auth.secretKey);
  const outgoing = new Headers();
  for (const [key, value] of Object.entries(signed)) {
    if (key.toLowerCase() !== "host") outgoing.set(key, String(value));
  }
  const res = await fetch(url, { method: "POST", headers: outgoing, body });
  const text = await res.text();
  console.log(`[${label}] -> ${res.status}${text.includes("TM.00001041") ? "  并发上限" : ""}  ${text.slice(0, 90).replace(/\s+/g, " ")}`);
  return res.status;
};

const base = { model: "GLM-5.1", messages: [{ role: "user", content: "say ok" }], max_tokens: 4 };

// 1) 完整的流式请求（读到结束）
console.log("步骤 1：一条完整的流式请求");
await send("stream 完整", JSON.stringify({ ...base, stream: true }));

// 2) 立刻再打一条非流式：如果流式请求没释放名额，这里就会撞上限
console.log("\n步骤 2：紧接着一条普通请求");
await send("非流式", JSON.stringify({ ...base, stream: false }));

// 3) 再打一条流式但中途放弃（模拟 agent 被取消）
console.log("\n步骤 3：一条被中途放弃的流式请求");
const url = `${INFERHUB_BASE}chat/completions`;
const body = JSON.stringify({ ...base, stream: true, max_tokens: 200 });
const controller = new AbortController();
const headers = {
  "content-type": "application/json",
  "x-security-token": auth.securityToken,
  "x-language": "zh-cn",
  "x-ot-client-type": "magpie-codearts-auth",
  "x-ot-client-version": "0.1.0",
};
const signed = signRequest({ method: "POST", url, headers, body }, auth.accessKey, auth.secretKey);
const outgoing = new Headers();
for (const [key, value] of Object.entries(signed)) {
  if (key.toLowerCase() !== "host") outgoing.set(key, String(value));
}
const res = await fetch(url, { method: "POST", headers: outgoing, body, signal: controller.signal });
console.log("  已连接:", res.status, "，读完第一个 chunk 后取消");
const reader = res.body.getReader();
await reader.read();
controller.abort();
console.log("  已 abort");
await new Promise((resolve) => setTimeout(resolve, 1500));

console.log("\n步骤 4：取消之后再打一条普通请求");
await send("中止后", JSON.stringify({ ...base, stream: false }));
process.exit(0);
