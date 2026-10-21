const urls = [
  "https://opengw.developer.huaweicloud.com/api/v1/user/tokens/balance",
  "https://opengw.developer.huaweicloud.com/api/v1/benefit/claim",
  "https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager/v1/package/overview",
  "https://snap-access.cn-north-4.myhuaweicloud.com/v1/ops/delivery?channel=DESKTOP",
  "https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager/v1/member/roles"
];
for (const u of urls) {
  try {
    const r = await fetch(u, { method: "GET" });
    const t = await r.text();
    console.log(`GET ${u} -> ${r.status} ${t.slice(0, 200).replace(/\s+/g, " ")}`);
  } catch (e) { console.log(`GET ${u} -> ERROR ${e.message}`); }
}
