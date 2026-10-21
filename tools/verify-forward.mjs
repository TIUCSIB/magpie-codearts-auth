// 用本机 magpie 保存的 CodeArts 账号，按 magpie 的真实调用方式走一遍插件：
// loader().fetch 转发 → auth.usage 余额 → provider.models 模型列表。
// 只发一条 max_tokens=1 的推理请求；不打印任何凭据值。
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { CodeArtsAuthPlugin, _internal } from "../index.mjs";

const { INFERHUB_BASE } = _internal;
const authFile = process.argv[2] ?? path.join(os.homedir(), ".config", "magpie", "plugin-auth.json");
const entry = JSON.parse(fs.readFileSync(authFile, "utf8")).codearts;
const auth = Array.isArray(entry) ? entry[0] : entry;
if (!auth) throw new Error("plugin-auth.json 里没有 codearts 账号");

const hooks = await CodeArtsAuthPlugin({ directory: path.dirname(authFile) }, {});
const getAuth = async () => auth;

// 1) 转发：模拟 magpie / AI SDK 实际带的头
const config = await hooks.auth.loader(getAuth);
console.log("baseURL            :", config.baseURL);
const res = await config.fetch(`${INFERHUB_BASE}chat/completions`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: "Bearer ",
    accept: "*/*",
    "user-agent": "Bun/1.4.3",
    "accept-encoding": "gzip, deflate",
    "x-opencode-directory": "/tmp",
  },
  body: JSON.stringify({
    model: "GLM-5.1",
    messages: [{ role: "user", content: "reply with the single word: pong" }],
    max_tokens: 1,
    stream: false,
  }),
});
const text = await res.text();
console.log("chat/completions   :", res.status, `Sign-In=${res.headers.get("X-Magpie-Sign-In") ?? "-"}`);
console.log("body               :", text.slice(0, 180).replace(/\s+/g, " "));

// 2) 余额 / 额度
const usage = await hooks.auth.usage(getAuth);
console.log("\nusage.plan         :", usage.plan ?? "-");
console.log("usage.balance      :", usage.balance ?? "-");
console.log("usage.error        :", usage.error ?? "-");
console.log("usage.signIn       :", usage.signIn ?? "-");
for (const window of usage.windows ?? []) {
  console.log(`  window ${window.name}: used=${window.used ?? "-"} ${window.display ?? ""}`);
}

// 3) 模型列表
const models = await hooks.provider.models({ models: { "GLM-5.1": { name: "GLM-5.1" } } }, { auth });
console.log("\nmodels             :", Object.keys(models).length, Object.keys(models).slice(0, 6).join(", "), "…");

// 4) 真实签到：delivery → claim → confirm
const checkin = await _internal.runCheckin(auth);
console.log("\ncheckin.status     :", checkin.status);
console.log("checkin.message    :", checkin.message ?? "-");
if (checkin.campaign) {
  console.log(
    `checkin.campaign   : #${checkin.campaign.campaignId} ${checkin.campaign.title} +${checkin.campaign.benefitAmount} ${checkin.campaign.benefitUnit}`,
  );
}
if (checkin.confirmed) console.log("checkin.confirmed  :", checkin.confirmed.ok, checkin.confirmed.message ?? "-");

// 签到后再看一次积分，确认真的到账了
const after = await hooks.auth.usage(getAuth);
console.log("\n积分（签到后）      :", after.balance ?? "-");
process.exit(0);
