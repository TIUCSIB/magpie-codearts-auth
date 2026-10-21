# 逆向证据链

插件里的每个端点、鉴权方式和请求格式都来自对本机 CodeArts 客户端的静态分析、
运行时日志与无凭据探测，不是猜的。下表逐条给出结论与来源。

分析对象：`D:\CodeArts`（CodeArts 0.2.6，kernel v0.2.22）。

| 结论 | 证据 |
| --- | --- |
| 客户端认证参数（clientId `codearts`、STS 域名、回调 `/oauth/callback`、plugin `snap_AIIDE 5.1.0`、登录超时 300s） | `D:\CodeArts\resources\product.json` 的 `auth` 段 |
| 授权 URL 参数、PKCE 生成、DPoP JWT 结构、token 交换与续期表单 | `app.asar` → `out/main/index.js`（`generatePkcePair` / `generateDpopJWE` / `exchangeToken` / `refreshToken`，L1053–1120、L2183–2243、L2454） |
| 华为云 SDK-HMAC-SHA256 签名算法（canonical request → Authorization 头） | 同上 `sign()` L1083–1148；`index.mjs` 里逐行等价移植 |
| 余额端点 `GET /api/v1/user/tokens/balance` | 同上 `BenefitService.getBalance` L3731–3765 |
| 签到端点 `POST /api/v1/benefit/claim[?channel=]` | 同上 `claimBenefit` L3679–3714；并见运行日志 `%APPDATA%\codearts\app-logs\logs\main.log` 09:26:42「Claiming benefit: https://opengw.developer.huaweicloud.com/api/v1/benefit/claim」→ `error_code=4000` |
| 额度/套餐结构（`metrics[]`、`package_credit_*`、`package_user_used_token`） | 同上 `PackageInfo` L17320–17453 |
| 福利/权益网关端点 | 同上 `getGatewayConfigByChannel` / `getWelfareDelivery` / `claimWelfare` / `confirmWelfare` L3794–3996 |
| 推理端点与协议 | kernel 内字符串：`crates\llm\adapters\src\inferhub_llm\mod.rs`、`crates\external-plugins\image-analyze\src\vlm_caller.rs`（`inferhubBaseUrl` + `/chat/completions`、`data:[DONE]`、`/choices/0/delta/content`、`Using HWS SDK-HMAC-SHA256 signing.`） |
| `POST /api/v2/chat/completions` 真实存在且要鉴权 | 无凭据探测 → `401 APIG.0301 "x-auth-token not found"`（路径存在且鉴权失败，而非 404） |
| 其余端点路由存在性 | 同一批探测：`/api/v1/user/tokens/balance`、`/api/v1/benefit/claim`、`/v1/ops/delivery`、`/snap-manager/v1/member/roles` 均返回 401 APIG.0301 |
| kernel 的身份（Rust、版本线索） | REA `inspect_rust_binary` 证据 `ev_cead36e3…9e3cbd`：PE amd64、106,663,352 字节、sha256 `a5b78f328772…d056`、推断 rustc commit `59807616e1fa…3860` |

## 工具

| 脚本 | 用途 |
| --- | --- |
| `tools/asar.mjs` | 直接解析 asar 头，按需 list / extract / cat / grep（整包 296 MB、16474 条，不整包解压） |
| `tools/strings.mjs` | 扫描二进制里的 ASCII / UTF-16LE 字符串并按正则过滤 |
| `tools/dump-context.mjs` | 打印某个字节串出现位置前后的可打印上下文（定位 Rust 源码路径、头名、错误码） |
| `tools/probe.mjs` / `tools/probe-get.mjs` | 无凭据探测端点存在性（401 vs 404） |
| `tools/probe-login.mjs` | 调用插件的 `authorize()`，验证授权 URL、本地回调服务器与 token 交换链路 |

复现示例：

```bash
node tools/asar.mjs D:\CodeArts\resources\app.asar extract out/main/index.js extracted/main-index.js
node tools/dump-context.mjs D:\CodeArts\resources\bin\agent-kernel.exe "hws_security_token" 300
node tools/probe-login.mjs
```

## 验证结果

1. **单测**：`bun test` → 15 pass / 0 fail（签名确定性、SignedHeaders 字典序、PKCE base64url、
   DPoP 用公钥验签、登录 URL 参数、账号字段映射、额度窗口解析）。
2. **magpie 真实加载**（沙箱 `HOME` + `MAGPIE_ADDR=127.0.0.1:3499`）：

   ```
   tools  codearts_balance, codearts_checkin, codearts_welfare
   codearts (CodeArts (码道), 4 models)  not signed in · magpie plugin login codearts
   ```

   `magpie plugin --json` 同时确认 `methods: oauth + api`、`usage: true`、模型列表已声明。
3. **登录链路端到端**（`tools/probe-login.mjs`）：`authorize()` 产出的 URL 与客户端一致；本地回调
   服务器收到回调返回 200；`callback()` 带 DPoP 打到华为云 STS（假授权码 → HTTP 400，说明请求结构
   与 DPoP 被接受，而不是签名/格式错误）。
