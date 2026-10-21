# magpie-codeArt-auth

用 magpie-docs 规范为华为云 **CodeArts（码道 CodeArts Doer）** 写的 **Magpie 反代插件**：
OAuth2 登录 + 余额提醒 + 每日签到。

```
magpie-codeArt-auth/
├── opencode-codearts-auth/          ← 插件本体（可直接 magpie plugin add）
│   ├── index.mjs                    ← config / auth（OAuth2+PKCE+DPoP）/ loader / provider.models / auth.usage / tool
│   ├── package.json                 ← npm 包元数据 + magpie 字段（maxConcurrency、options）
│   ├── README.md                    ← 给用户看的说明（magpie 插件详情页显示）
│   └── test/plugin.test.mjs         ← 15 个单测（bun test）
├── extracted/                       ← 从 CodeArts 客户端 app.asar 提取的主进程包（主要证据）
└── tools/                           ← 逆向与验证脚本（asar 读取、字符串/上下文提取、登录链路探针）
```

## 它是怎么反代的

| 环节 | 实现 |
| --- | --- |
| 登录 | `authorize()` 生成 PKCE + DPoP(ES256) → 起 127.0.0.1 随机端口回调服务器 → 打开 `codearts.huaweicloud.com/portal/authorize` → 拿到 `code` → `POST /v1/oauth2/tokens` 换华为云 STS 凭证（AK/SK/SecurityToken）+ `refresh_token` |
| 请求 | `loader()` 把每个 OpenAI Chat Completions 请求发往 `https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions`，逐请求做 `SDK-HMAC-SHA256` 签名并带 `X-Security-Token` |
| 续期 | `auth.refresh` 用保存的 `refresh_token` + 同一 DPoP 密钥在到期前续期，失败抛 `signIn: "expired"` |
| 余额提醒 | `auth.usage` 读套餐概览 + 余额，产出 `plan / balance / until / windows[]`，显示在 magpie 额度窗口、`magpie quota`、`GET /v1/magpie/quotas` |
| 签到 | `tool.codearts_checkin` 打 `POST /api/v1/benefit/claim` 并回读余额；`autoCheckin` 选项可让每天的第一次额度刷新顺带签到 |
| 模型列表 | `provider.models` 组合「内置 inferhub 模型」+「benefit / education 权益渠道模型」，失败时回退到内置默认列表 |

## 逆向证据链

对本地实例 `D:\CodeArts`（CodeArts 0.2.6 / kernel v0.2.22）分析，结论与来源一一对应：

| 结论 | 证据 |
| --- | --- |
| 客户端认证参数（clientId=codearts、sts 域名、logging redirect `/oauth/callback`、plugin `snap_AIIDE` 5.1.0） | `D:\CodeArts\resources\product.json` 的 `auth` 段 |
| 授权 URL 参数、PKCE 生成、DPoP JWT 结构、token 交换与续期表单 | `extracted/main-index.js`（`generatePkcePair` / `generateDpopJWE` / `exchangeToken` / `refreshToken`，L1053–1120、L2183–2243、L2454） |
| 华为云 SDK-HMAC-SHA256 签名算法（canonical request → Authorization 头） | `extracted/main-index.js` `sign()` L1083–1148（插件内逐行等价移植） |
| 余额端点 `GET /api/v1/user/tokens/balance` | `extracted/main-index.js` `BenefitService.getBalance` L3731–3765 |
| 签到端点 `POST /api/v1/benefit/claim[?channel=]` | `extracted/main-index.js` `claimBenefit` L3679–3714；**运行日志** `%APPDATA%\codearts\app-logs\logs\main.log` 09:26:42「Claiming benefit: https://opengw.developer.huaweicloud.com/api/v1/benefit/claim」→ `error_code=4000` |
| 额度/套餐结构（metrics、package_credit_*、package_user_used_token） | `extracted/main-index.js` `PackageInfo` L17320–17453 |
| 推理端点与协议 | kernel 内 `crates\llm\adapters\src\inferhub_llm\mod.rs`、`crates\external-plugins\image-analyze\src\vlm_caller.rs` 的字符串（`inferhubBaseUrl` + `/chat/completions`、`data:[DONE]`、`/choices/0/delta/content`、`Using HWS SDK-HMAC-SHA256 signing.`） |
| `POST /api/v2/chat/completions` 真实存在且要鉴权 | 无凭据探测返回 `401 APIG.0301 "x-auth-token not found"`（路径存在，鉴权缺失——不是 404） |
| main.log 的套餐/福利/权益调用链 | `%APPDATA%\codearts\app-logs\logs\main.log`（benefit-gateway-config、ops/delivery、snap-manager/v1/package/overview） |
| kernel 是 Rust 程序、其 sha256 与 rustc 版本线索 | REA `inspect_rust_binary`，证据 `ev_cead36e3…9e3cbd`：PE amd64、106,663,352 字节、sha256 `a5b78f328772…d056`、rustc commit `59807616e1fa…3860`（推断） |

> 说明：整包 `app.asar` 有 296 MB / 16474 个条目，因此用 `tools/asar.mjs` 直接解析 asar 头按需取文件，
> 再用 `tools/strings.mjs` / `dump-context.mjs` 定位字符串上下文；REA 用于对 native 产物给出可引用的
> 独立证据（kernel 身份 + Rust 构建事实）。

## 验证结果

1. **单测**：`bun test` → `15 pass / 0 fail`（签名确定性、SignedHeaders 字典序、PKCE base64url、DPoP 用公钥验签、登录 URL 参数、账号字段映射、额度窗口解析）。
2. **magpie 真实加载**（沙箱 `HOME`，`MAGPIE_ADDR=127.0.0.1:3499`）：

```
✓ added ...\opencode-codearts-auth
  tools  codearts_balance, codearts_checkin, codearts_welfare
  codearts (CodeArts (码道), 4 models)  not signed in · magpie plugin login codearts
```

   `magpie plugin --json` 同时确认：`methods: oauth + api`、`usage: true`、模型列表已声明。
3. **登录链路端到端**（`tools/probe-login.mjs`）：`authorize()` 产出的 URL 与客户端一致，
   本地回调服务器收到回调返回 200，`callback()` 带着 DPoP 头打到华为云 STS（假授权码返回 HTTP 400——
   说明请求结构与 DPoP 被接受，而不是签名/格式错误）。

## 使用

```bash
magpie plugin add ./opencode-codearts-auth
magpie plugin login codearts        # Sign in with HUAWEI CodeArts
magpie quota                        # 余额 / 额度窗口
magpie provider test codearts       # 打一个最小请求
magpie plugin options codearts '{"channel":"benefit","autoCheckin":true}'
```

## 已知边界

- 「余额提醒」的落点是 magpie 的额度展示（供应商账号卡片、`magpie quota`、`GET /v1/magpie/quotas`）——
  magpie 的插件接口里没有「阈值告警」钩子（文档只定义 `auth.usage` 上报额度）。想要主动提醒，
  让 agent 调 `codearts_balance` 工具，或开 `autoCheckin` 让每天第一次额度刷新顺带签到并回填窗口。
- 「签到」对应 CodeArts 的**权益领取**（`/api/v1/benefit/claim`）；该接口在未开通权益时会返回
  `error_code=4000` 之类的业务错误，插件会如实回报而不是编造成功。
- 额度、余额接口的字段名取自客户端解析逻辑，接口改版时 `auth.usage` 会降级成错误文本，不影响对话转发。
- 拿到真实账号后才能确定每次签到的奖励文案与 `result` 结构；当前实现只把接口原样结果带出来。
