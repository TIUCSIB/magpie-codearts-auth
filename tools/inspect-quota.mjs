// 打印 CodeArts 额度相关端点的真实响应结构（凭据值不打印）。
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { _internal } from "../index.mjs";

const { SNAP_ENGINE, BENEFIT_API, signRequest } = _internal;
const authFile = process.argv[2] ?? path.join(os.homedir(), ".config", "magpie", "plugin-auth.json");
const entry = JSON.parse(fs.readFileSync(authFile, "utf8")).codearts;
const auth = Array.isArray(entry) ? entry[0] : entry;

const call = async (url, method = "GET", body, extra = {}) => {
  const headers = {
    "x-security-token": auth.securityToken,
    "content-type": "application/json",
    "x-language": "zh-cn",
    "agent-type": "PromptCenter",
    ...extra,
  };
  const signed = signRequest({ method, url, headers, body: body ?? "" }, auth.accessKey, auth.secretKey);
  const outgoing = new Headers();
  for (const [key, value] of Object.entries(signed)) {
    if (key.toLowerCase() === "host") continue;
    outgoing.set(key, String(value));
  }
  const res = await fetch(url, { method, headers: outgoing, body: method === "GET" ? undefined : body });
  const text = await res.text();
  console.log(`\n### ${method} ${url} -> ${res.status}`);
  console.log(text.slice(0, 1600));
  return text;
};

await call(`${SNAP_ENGINE}/snap-manager/v1/package/overview`);
await call(`${SNAP_ENGINE}/snap-manager/v1/statistics/plugin`);
await call(`${SNAP_ENGINE}/snap-manager/v1/member/roles`);
await call(`${BENEFIT_API}/api/v1/user/tokens/balance`);
await call(`${BENEFIT_API}/api/v1/user/tokens/balance?channel=benefit`);
await call(`${BENEFIT_API}/api/v1/benefit/claim`);
process.exit(0);
