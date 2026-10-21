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

## 真实账号上的运行时代验证

用本机 magpie 保存的 CodeArts 账号（`tools/verify-forward.mjs`、`tools/inspect-quota.mjs`、
`tools/inspect-welfare.mjs`）跑出来的事实，修正/确认了静态分析的几处：

| 事实 | 依据 |
| --- | --- |
| **额度来源是 `snap-manager/v1/statistics/plugin`**，`package/overview` 现网 404（`APIG.0101`） | `tools/inspect-quota.mjs`；`metrics[]` 给出 `package_credit_amount/used/remain`（15500 / 974.89 / 14525.11） |
| 模型列表来源是同一响应的 `model_metrics[]` | 8 个可用模型（GLM-5.2、Qwen3-VL-235B、kimi-k2.6-vl、openpangu-2.0-flash/pro、glm-5.3、glm-5.2-sft-harmony、deepseek-v4.1-flash） |
| **每日签到是 `USER_LOGIN` campaign，走 `delivery → claim → confirm`** | `tools/inspect-welfare.mjs`：#1「每日签到领1000积分」`claimable=true` → 领取后 `status=CLAIMED`、积分 14525.11 → **15525.11**（总额度 15500 → 16500） |
| 福利活动共 4 个（新人 4000 / 邀请 1000 / 学生认证 4000 / 每日签到 1000） | 同上 |
| opengw 的 `balance`、`benefit/claim` 对本账号返回 `error_code 4000 invalid channel, group not found`；`benefit/education-gateway-config` 的 `enabled=false` | 同上；所以这两条路径只在渠道开通后才有意义，插件不当成错误 |
| **推理 401 `verify ak sk signature fail` 的根因**：把调用方传来的头（含 `authorization: Bearer`）全部纳入签名，随后 `authorization` 又被签名值覆盖，服务端按实际请求头验签必然失败 | `tools/repro-401.mjs`：全量头 → 401；白名单头 → 200。修复后 `tools/verify-forward.mjs` 在带 `authorization`/`accept`/`accept-encoding` 的真实形态下稳定 200 |
| `maas_type=benefit` 在本账号会得到 `4004 benefit not found` | `tools/diagnose-inferhub.mjs`；所以默认不发送该头 |
| 并发上限 `TM.00001041` 是**服务端按账号**记的活跃会话，插件无法查询或释放 | kernel 日志只暴露 `wss://snap-access.cn-north-4.myhuaweicloud.com/tunnel/ws?clientId=codearts-agent-<机器名>-<随机>` 与 `/snap-manager/v1/chat-session/heartbeat`；后者在现网所有方法都返回 404（未发布），也没有会话列表/关闭接口。`tools/probe-session.mjs`、`tools/probe-session-id.mjs` |
| 每次启动 CodeArts 客户端都会注册一条新 `clientId` 的隧道 | 两段 kernel 日志：`…-f8bdf0eb`（10:19）与 `…-51295932`（12:49），`clientName: DESKTOP-NTP8TMI` |
| 该限制是间歇性的：空闲时连续 8 次请求全部 200 | `tools/probe-session-id.mjs`（含带 `x-snap-client-id` / `clientId` / body `session_id` 等变体，无一被拒，说明服务端不按这些字段归并会话） |
| 插件默认并发 4 高于服务端上限 3，已降为 2；并对 `TM.00001041` 退避重试 | `package.json` 的 `magpie.maxConcurrency`、`index.mjs` 的 `forwardSigned`；`tools/verify-concurrency.mjs` 实测 4 并发全部 200 |

验证结果（本次）：

- `bun test` → **29 pass / 0 fail**；
- 转发：`POST /api/v2/chat/completions` → 200（GLM-5.1 正常回包）；
- 额度：`auth.usage` 输出 15525.11 / 16500 积分与 3 个有效窗口（总额/基础/赠送）；
- 签到：真实领取成功（+1000 积分），重复调用返回「今日已签到（CLAIMED）」。
