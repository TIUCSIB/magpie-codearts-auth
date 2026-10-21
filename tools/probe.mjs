const urls = [
  "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions",
  "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/models",
  "https://opengw.developer.huaweicloud.com/api/v1/user/tokens/balance",
  "https://snap-access.cn-north-4.myhuaweicloud.com/v1/benefit-gateway-config"
];
for (const u of urls) {
  try {
    const r = await fetch(u, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    const t = await r.text();
    console.log(`POST ${u} -> ${r.status} ${t.slice(0, 220).replace(/\s+/g, " ")}`);
  } catch (e) {
    console.log(`POST ${u} -> ERROR ${e.message}`);
  }
}
