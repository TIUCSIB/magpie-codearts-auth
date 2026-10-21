// 只打印结构：字段名、expires 的可读时间、各密钥的长度（不打印任何密钥值）。
import fs from "node:fs";

const file = process.argv[2];
const raw = JSON.parse(fs.readFileSync(file, "utf8"));

const summarize = (value, depth = 0) => {
  if (value === null || typeof value !== "object") return typeof value;
  const keys = Object.keys(value);
  return `{ ${keys.join(", ")} }`;
};

for (const [provider, entry] of Object.entries(raw)) {
  if (!/codeart/i.test(provider) && !/codeart/i.test(JSON.stringify(Object.keys(entry ?? {})))) {
    if (!/codeart/i.test(provider)) continue;
  }
  console.log(`\n=== provider key: ${provider} ===`);
  const accounts = Array.isArray(entry) ? entry : [entry];
  accounts.forEach((account, index) => {
    console.log(`-- account #${index} --`);
    console.log(`fields: ${Object.keys(account ?? {}).join(", ")}`);
    for (const [key, value] of Object.entries(account ?? {})) {
      if (typeof value === "string") {
        const isTime = /expir|until|date/i.test(key);
        const asDate = isTime && Number.isFinite(Number(value)) ? new Date(Number(value)) : null;
        const iso = /^\d{4}-\d{2}-\d{2}T/.test(value) ? value : asDate && !Number.isNaN(asDate.getTime()) ? asDate.toISOString() : null;
        console.log(`  ${key}: string(len=${value.length})${iso ? ` -> ${iso} (now-relative: ${((new Date(iso).getTime() - Date.now()) / 60000).toFixed(1)} min)` : ""}`);
      } else {
        console.log(`  ${key}: ${summarize(value)}`);
      }
    }
  });
}
