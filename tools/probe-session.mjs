// 探测 CodeArts 的会话上限机制：心跳端点要什么字段、当前请求是否仍被并发限制挡下。
// 使用本机 magpie 已保存的 CodeArts 账号；不打印凭据值。
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { _internal } from "../index.mjs";

const { SNAP_ENGINE, INFERHUB_BASE, signRequest } = _internal;
const authFile = process.argv[2] ?? path.join(os.homedir(), ".config", "magpie", "plugin-auth.json");
const entry = JSON.parse(fs.readFileSync(authFile, "utf8")).codearts;
const auth = Array.isArray(entry) ? entry[0] : entry;

const call = async (label, url, method = "GET", body) => {
  const headers = {
    "x-security-token": auth.securityToken,
    "content-type": "application/json",
    "x-language": "zh-cn",
    "x-ot-client-type": "CodeArts",
    "x-ot-client-version": "0.2.6",
    "plugin-name": "snap_AIIDE",
    "plugin-version": "5.1.0",
  };
  const signed = signRequest({ method, url, headers, body: body ?? "" }, auth.accessKey, auth.secretKey);
  const outgoing = new Headers();
  for (const [key, value] of Object.entries(signed)) {
    if (key.toLowerCase() !== "host") outgoing.set(key, String(value));
  }
  try {
    const res = await fetch(url, { method, headers: outgoing, body: method === "GET" ? undefined : body });
    console.log(`\n[${label}] ${method} ${url} -> ${res.status}`);
    console.log("   " + (await res.text()).slice(0, 400).replace(/\s+/g, " "));
  } catch (error) {
    console.log(`\n[${label}] -> ERROR ${error.message}`);
  }
};

// 1) 心跳端点要什么
await call("心跳 空 body", `${SNAP_ENGINE}/snap-manager/v1/chat-session/heartbeat`, "POST", "{}");
await call("心跳 session_id", `${SNAP_ENGINE}/snap-manager/v1/chat-session/heartbeat`, "POST", JSON.stringify({ session_id: "probe" }));
await call("心跳 chatSessionId", `${SNAP_ENGINE}/snap-manager/v1/chat-session/heartbeat`, "POST", JSON.stringify({ chatSessionId: "probe", status: "busy" }));
await call("心跳 GET", `${SNAP_ENGINE}/snap-manager/v1/chat-session/heartbeat`, "GET");

// 2) 有没有会话管理接口
await call("会话列表", `${SNAP_ENGINE}/snap-manager/v1/chat-session`, "GET");
await call("会话计数", `${SNAP_ENGINE}/snap-manager/v1/chat-session/count`, "GET");

// 3) 现在还能不能推理
const chatBody = JSON.stringify({
  model: "GLM-5.1",
  messages: [{ role: "user", content: "ping" }],
  max_tokens: 1,
  stream: false,
});
await call("推理", `${INFERHUB_BASE}chat/completions`, "POST", chatBody);
process.exit(0);
