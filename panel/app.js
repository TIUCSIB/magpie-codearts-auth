// 这个面板只读写插件自己的选项（plugins.json 里这一项），不做网络请求：
// 页面的内容安全策略是 connect-src 'none'，拿不到账号，也不该拿。
const auto = document.getElementById("auto");
const status = document.getElementById("status");
const hint = document.getElementById("autoHint");

await magpie.ready;

try {
  const options = (await magpie.options.get()) ?? {};
  // 默认开启：选项里没写也算开着（和插件代码里的默认值一致）
  auto.checked = options.autoCheckin !== false;
  const account = options.account ? `（账号：${options.account}）` : "";
  status.textContent = auto.checked
    ? `已开启每天自动签到${account}。签到结果会出现在额度卡片里。`
    : "当前是手动签到：需要时让 agent 调 checkin 工具。";
} catch (error) {
  status.textContent = `读取选项失败：${error?.message ?? error}`;
}

auto.addEventListener("change", async () => {
  try {
    const options = (await magpie.options.get()) ?? {};
    await magpie.options.set({ ...options, autoCheckin: auto.checked });
    status.textContent = auto.checked
      ? "已开启每天自动签到：magpie 下次刷新额度时会顺带领取（一天一次）。"
      : "已关闭自动签到。";
  } catch (error) {
    status.textContent = `保存失败：${error?.message ?? error}`;
    auto.checked = !auto.checked;
  }
});

hint.addEventListener("click", () => auto.focus());
