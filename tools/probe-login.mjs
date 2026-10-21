// 直接调用插件的 authorize()，确认登录 URL 与回调服务器都能就绪（不会打开浏览器、不会登录）。
// usage: node probe-login.mjs
import { CodeArtsAuthPlugin } from "../opencode-codearts-auth/index.mjs";

const hooks = await CodeArtsAuthPlugin({ directory: process.cwd() });
const method = hooks.auth.methods[0];
const started = await method.authorize();

console.log("method type :", method.type);
console.log("label       :", method.label);
console.log("flow        :", started.method);
console.log("instructions:", started.instructions);
console.log("url         :", started.url);

const url = new URL(started.url);
console.log("port param  :", url.searchParams.get("port"));
console.log("challenge   :", url.searchParams.get("code_challenge")?.slice(0, 24), "…");

// 回调服务器是否真的在监听：拿它给的端口发一个假的成功回调
const port = Number(url.searchParams.get("port"));
const res = await fetch(`http://127.0.0.1:${port}/oauth/callback?code=FAKE_CODE`);
console.log("callback    :", res.status, (await res.text()).replace(/\s+/g, " ").slice(0, 60));

const outcome = await started.callback();
console.log("exchange    :", outcome.type, "|", String(outcome.error ?? "").slice(0, 120));
process.exit(0);
