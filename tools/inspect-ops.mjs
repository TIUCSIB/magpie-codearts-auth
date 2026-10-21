import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { _internal } from "../index.mjs";
const { SNAP_ENGINE, signRequest } = _internal;
const authFile = path.join(os.homedir(), ".config", "magpie", "plugin-auth.json");
const entry = JSON.parse(fs.readFileSync(authFile, "utf8")).codearts;
const auth = Array.isArray(entry) ? entry[0] : entry;
const call = async (url) => {
  const headers = { "x-security-token": auth.securityToken, "content-type": "application/json", "x-language": "zh-cn", "agent-type": "PromptCenter", "x-snap-traceid": "11111111-2222-3333-4444-555555555555" };
  const signed = signRequest({ method: "GET", url, headers, body: "" }, auth.accessKey, auth.secretKey);
  const h = new Headers(); for (const [k, v] of Object.entries(signed)) { if (k.toLowerCase() !== "host") h.set(k, String(v)); }
  const res = await fetch(url, { method: "GET", headers: h });
  console.log(`\n### GET ${url} -> ${res.status}`); console.log((await res.text()).slice(0, 900));
};
for (const p of ["/v1/ops/delivery?channel=DESKTOP", "/v1/benefit-gateway-config", "/v1/education-gateway-config", "/v1/llm/vendors"]) await call(SNAP_ENGINE + p);

