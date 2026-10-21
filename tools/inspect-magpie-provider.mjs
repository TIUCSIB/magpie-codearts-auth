import fs from "node:fs";
import os from "node:os";
import path from "node:path";
const p = path.join(os.homedir(), ".config", "magpie", "providers.json");
const data = JSON.parse(fs.readFileSync(p, "utf8"));
const find = (node, out = []) => {
  if (!node || typeof node !== "object") return out;
  for (const [k, v] of Object.entries(node)) {
    if (k === "accountConcurrency" && v && typeof v === "object") out.push(v);
    find(v, out);
  }
  return out;
};
const all = find(data);
console.log("accountConcurrency 条数:", all.length);
for (const entry of all.slice(0, 5)) console.log(JSON.stringify(entry, null, 2).slice(0, 500));
const codearts = JSON.stringify(data).includes("codearts");
console.log("providers.json 含 codearts:", codearts);
const providers = Array.isArray(data.providers) ? data.providers : (data.providers ? Object.values(data.providers) : []);
for (const provider of providers) {
  if (String(provider?.id ?? "").includes("codearts")) {
    const { models, ...rest } = provider;
    console.log("codearts provider 设置:", JSON.stringify(rest, null, 2).slice(0, 800));
  }
}
