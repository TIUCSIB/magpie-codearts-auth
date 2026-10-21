// 打印福利活动列表（找每日签到 campaign）与额度指标摘要。
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { _internal } from "../index.mjs";

const { SNAP_ENGINE, signRequest } = _internal;
const authFile = process.argv[2] ?? path.join(os.homedir(), ".config", "magpie", "plugin-auth.json");
const entry = JSON.parse(fs.readFileSync(authFile, "utf8")).codearts;
const auth = Array.isArray(entry) ? entry[0] : entry;

const get = async (url, extra = {}) => {
  const headers = {
    "x-security-token": auth.securityToken,
    "content-type": "application/json",
    "x-language": "zh-cn",
    "agent-type": "PromptCenter",
    ...extra,
  };
  const signed = signRequest({ method: "GET", url, headers, body: "" }, auth.accessKey, auth.secretKey);
  const outgoing = new Headers();
  for (const [key, value] of Object.entries(signed)) {
    if (key.toLowerCase() !== "host") outgoing.set(key, String(value));
  }
  const res = await fetch(url, { method: "GET", headers: outgoing });
  return JSON.parse(await res.text());
};

const delivery = await get(`${SNAP_ENGINE}/v1/ops/delivery?channel=DESKTOP`, {
  "x-snap-traceid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
});
console.log("delivery.code:", delivery.code, "items:", delivery.data?.items?.length);
for (const item of delivery.data?.items ?? []) {
  console.log(
    `  #${item.campaignId} type=${item.type} status=${item.status} claimable=${item.claimable} ` +
      `amount=${item.benefitAmount} ${item.benefitUnit} pending=${item.pendingCount} title=${item.title}`,
  );
}

const stats = await get(`${SNAP_ENGINE}/snap-manager/v1/statistics/plugin`);
console.log("\nmetrics:");
for (const metric of stats.metrics ?? []) {
  console.log(
    `  ${metric.name}: credit ${metric.package_credit_used ?? "-"}/${metric.package_credit_amount ?? "-"}` +
      ` remain=${metric.package_credit_remain ?? "-"} show=${metric.show}`,
  );
}
const models = stats.model_metrics ?? [];
console.log(`\nmodel_metrics: ${models.length}`);
console.log("  " + models.map((m) => `${m.model_id}${m.enable ? "" : "(off)"}`).join(", "));
process.exit(0);
