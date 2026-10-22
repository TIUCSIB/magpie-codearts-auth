// 对比：账号 model_metrics 里有的模型 vs magpie 列表里多出来的模型（例如 glm-5.3-flash）。
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { _internal } from "../index.mjs";

const { INFERHUB_BASE, signRequest, fetchQuotaStats, modelsFromStats } = _internal;
const authFile = process.argv[2] ?? path.join(os.homedir(), ".config", "magpie", "plugin-auth.json");
const entry = JSON.parse(fs.readFileSync(authFile, "utf8")).codearts;
const auth = Array.isArray(entry) ? entry[0] : entry;

const stats = await fetchQuotaStats(auth);
const available = modelsFromStats(stats).map((model) => model.id);
console.log("账号可用的模型:", available.join(", "), "\n");

const ask = async (model) => {
  const url = `${INFERHUB_BASE}chat/completions`;
  const body = JSON.stringify({ model, messages: [{ role: "user", content: "hi" }], max_tokens: 1, stream: false });
  const headers = {
    "content-type": "application/json",
    "x-security-token": auth.securityToken,
    "x-language": "zh-cn",
    "x-ot-client-type": "opencode-codearts-auth",
    "x-ot-client-version": "0.1.0",
  };
  const signed = signRequest({ method: "POST", url, headers, body }, auth.accessKey, auth.secretKey);
  const outgoing = new Headers();
  for (const [key, value] of Object.entries(signed)) {
    if (key.toLowerCase() !== "host") outgoing.set(key, String(value));
  }
  const res = await fetch(url, { method: "POST", headers: outgoing, body });
  const text = await res.text();
  console.log(`[${model}] -> ${res.status}  ${text.slice(0, 220).replace(/\s+/g, " ")}`);
};

// 用户在用的、但不在账号列表里的，和账号列表里的各试一个
for (const model of ["glm-5.3-flash", "deepseek-v4-flash", "glm-5.3", "GLM-5.2"]) {
  await ask(model);
}
process.exit(0);
