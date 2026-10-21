// 并发验证：同时发多个请求，看「并发会话上限」是否被退避重试吸收。
// 每个请求 max_tokens=1，消耗极小；不打印凭据。
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { CodeArtsAuthPlugin, _internal } from "../index.mjs";

const { INFERHUB_BASE } = _internal;
const args = process.argv.slice(2);
const concurrency = Number(args.find((arg) => /^\d+$/.test(arg)) ?? 4);
const authFile =
  args.find((arg) => !/^\d+$/.test(arg)) ?? path.join(os.homedir(), ".config", "magpie", "plugin-auth.json");
const entry = JSON.parse(fs.readFileSync(authFile, "utf8")).codearts;
const auth = Array.isArray(entry) ? entry[0] : entry;

const hooks = await CodeArtsAuthPlugin({ directory: path.dirname(authFile) }, {});
const config = await hooks.auth.loader(async () => auth);

// 统计实际发出的 HTTP 次数（含重试）
const realFetch = globalThis.fetch;
let httpCalls = 0;
globalThis.fetch = (...args) => {
  httpCalls += 1;
  return realFetch(...args);
};

const one = async (index) => {
  const res = await config.fetch(`${INFERHUB_BASE}chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " },
    body: JSON.stringify({
      model: "GLM-5.1",
      messages: [{ role: "user", content: `ping ${index}` }],
      max_tokens: 1,
      stream: false,
    }),
  });
  const text = await res.text();
  const limit = text.includes("TM.00001041");
  return `${res.status}${limit ? " (并发上限)" : ""}`;
};

const started = Date.now();
const results = await Promise.all(Array.from({ length: concurrency }, (_, index) => one(index)));
console.log(`并发 ${concurrency} 个请求，用时 ${Date.now() - started} ms`);
console.log("结果      :", results.join("  "));
console.log("HTTP 次数 :", httpCalls, `（重试 ${httpCalls - concurrency} 次）`);
console.log("结论      :", results.every((item) => item.startsWith("200")) ? "全部成功 ✅" : "仍有请求失败 ❌");
process.exit(0);
