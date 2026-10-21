# opencode-codearts-auth

Magpie（usemagpie.ai）供应商插件：用你的华为云 **CodeArts（码道）** 账号登录，把 CodeArts 的
inferhub 模型接进 magpie —— Claude Code / Codex / OpenCode / Gemini CLI 等所有 agent 都能用，
另外带**余额提醒**和**每日签到**。

- **OAuth2 登录**：授权码 + PKCE + DPoP(ES256)，和 CodeArts 桌面客户端同一条链路，换回华为云 STS
  临时凭证（AK/SK/SecurityToken），并自动续期；也支持直接填 `x-auth-token`。
- **余额提醒**：`auth.usage` 钩子把套餐额度、剩余 credits/tokens、到期时间报到 magpie 的账号卡片、
  `magpie quota` 和 `GET /v1/magpie/quotas`。
- **签到**：工具 `codearts_checkin`（领取当日权益并回读余额），可选每天自动签到一次。

## 安装

```bash
# GitHub（推荐）
magpie plugin add TIUCSIB/magpie-codearts-auth

# 也可以带 ref
magpie plugin add github:TIUCSIB/magpie-codearts-auth#main

# 本地文件夹（开发时）
magpie plugin add ./magpie-codearts-auth
```

装好后：

```bash
magpie plugin login codearts        # 选 “Sign in with HUAWEI CodeArts”
magpie plugin                       # codearts (CodeArts (码道), 4 models)  signed in
magpie provider test codearts       # 打一个最小请求
magpie quota                        # 余额 / 额度窗口
```

应用里：插件 → 添加插件 → 填 `TIUCSIB/magpie-codearts-auth`（或文件夹路径）→ 在 `codearts` 这一行点登录，
浏览器里用华为云账号完成授权。登录成功后 agent 就能用 `codearts/GLM-5.1` 这类模型。

> **关于 `bun add https://github.com/…` 报错**：Bun 不认裸 URL（会报 `Invalid dependency name` /
> `codeload… legacy.tar.gz 404`）。magpie 的 git 安装走 `owner/repo`、`github:owner/repo[#ref]` 或
> `git+https://…`；另外仓库根目录必须有 `package.json`，插件加载的文件也必须提交进仓库 —— 本仓库满足这两点。

## 端点与鉴权

每个请求都带华为云 `SDK-HMAC-SHA256` 签名（`Authorization: SDK-HMAC-SHA256 Access=…`）与
`X-Security-Token` / `X-Sdk-Date`，和 CodeArts 客户端自己的网关调用一致。**签名只覆盖插件自己设置的那几个头**
（`content-type`、`host`、`x-sdk-date`、`x-security-token`、`x-language`、`plugin-name/version`、`x-ot-client-*`、可选的 `maas_type`）；
`authorization`、`accept`、`accept-encoding`、`user-agent` 这些由传输层和框架自己处理，纳入签名会让服务端验签失败。

| 用途 | 方法与端点 |
| --- | --- |
| 授权页 | `GET https://codearts.huaweicloud.com/portal/authorize?client_id=codearts&port=<本地端口>&code_challenge=…&ticket_id=…&plugin-name=snap_AIIDE&plugin-version=5.1.0` |
| 换 token / 续期 | `POST https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens`（`authorization_code` / `refresh_token`，带 `DPoP` 头） |
| 账号信息 | `GET https://sts.cn-north-4.myhuaweicloud.com/v5/caller-identity` |
| **推理（OpenAI 兼容）** | `POST https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions` |
| **积分额度（余额提醒）** | `GET https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager/v1/statistics/plugin`（`metrics[]` 的 `package_credit_*` + `model_metrics[]` 的模型列表） |
| **每日签到** | `GET /v1/ops/delivery?channel=DESKTOP` → 找 `type=USER_LOGIN` 且 `claimable=true` 的活动 → `POST /v1/ops/claim` → `POST /v1/ops/confirm`（都在 `https://snap-access.cn-north-4.myhuaweicloud.com`） |
| 福利活动列表 | `GET https://snap-access.cn-north-4.myhuaweicloud.com/v1/ops/delivery?channel=DESKTOP` |
| 权益渠道余额 | `GET https://opengw.developer.huaweicloud.com/api/v1/user/tokens/balance[?channel=benefit]`（渠道未开通时返回 `error_code 4000`） |
| 权益渠道领取 | `POST https://opengw.developer.huaweicloud.com/api/v1/benefit/claim[?channel=benefit]`（渠道未开通时返回 `error_code 4000`） |
| 权益渠道开关 | `GET https://snap-access.cn-north-4.myhuaweicloud.com/v1/{benefit,education}-gateway-config` |
| 渠道模型列表 | `GET https://opengw.developer.huaweicloud.com/api/v1/gateway/config[?channel=education]` |

返回体约定：多数接口是 `{ "error_code": "0000", "result": … }`；`/v1/ops/*` 用 `{ code, data }`。

> `/snap-manager/v1/package/overview` 在客户端代码里存在，但现网返回 `404 APIG.0101`（未发布），所以额度一律取
> `statistics/plugin`。

## 插件选项

```bash
magpie plugin options codearts '{"channel":"benefit","autoCheckin":true}'
```

| 选项 | 默认 | 作用 |
| --- | --- | --- |
| `channel` | `benefit` | 权益渠道：`benefit` 或 `education`，也是签到时带的渠道参数 |
| `maasType` | 空 | 给推理请求加 `maas_type` 头。**默认不要填**：账号没有 benefit 渠道时带了它会得到 `4004 benefit not found` |
| `autoCheckin` | `false` | 每天第一次刷新额度时自动签到一次（状态写在 magpie 配置目录的 `codearts-checkin.json`） |
| `account` | 空 | 多账号时指定工具用哪个账号（按 accountId / 用户名前缀匹配） |

## 工具

装了插件后，它们经 magpie 的内置 MCP（`http://127.0.0.1:3425/mcp/magpie/tools`）暴露给所有 agent：

- `codearts_checkin` —— 每日签到：找可领的 `USER_LOGIN` 活动并领取，回读积分余额；已签到时如实回复「今日已签到（CLAIMED）」；
- `codearts_balance` —— 积分余额、额度窗口（总额/基础/赠送）、可用模型；
- `codearts_welfare` —— 列出福利中心全部活动与领取状态（只读，不自动领取）。

## 续期与登录状态

STS 凭证约 1 小时有效。插件用 `auth.refresh` 在到期前 10 分钟续一次（同一时间只续一次）。续期需要登录时
保存的 PKCE `code_verifier` 与 DPoP 私钥（ES256），它们随凭证一起存在 magpie 的 `plugin-auth.json`（权限 600）。

只有**明确的**登录失效（`invalid_grant` / 401 / 403）才会返回带 `signIn: "expired"` 的错误去标记账号；
网络抖动和 5xx 不会。反过来，如果 STS 还没过期却收到 401/403，插件会给响应加
`X-Magpie-Sign-In: kept`，避免一次误判就把账号打成「需要重新登录」。

## 排错

| 现象 | 原因与处理 |
| --- | --- |
| `401 … Incorrect IAM authentication information: verify ak sk signature fail` | 签名覆盖了会被改写的头（早期版本会把 `authorization` 一起签进去）。0.1.0 起只签白名单头；更新插件即可。 |
| 账号刚登录就显示「需要重新登录」 | 409/401 被当成登录失效。先修掉上面的 401；插件现在只在真正失效时标记，并在 STS 未过期时加 `kept`。 |
| `4004 benefit not found` | 账号没有 benefit 权益渠道，却给请求加了 `maas_type=benefit`。把 `maasType` 选项留空。 |
| `error_code 4000 invalid channel, group not found` | opengw 的权益渠道未开通（`benefit-gateway-config` 的 `enabled=false`）。这不影响对话与每日签到；插件不会把它当成错误。 |
| 额度卡片空白 | 额度来自 `statistics/plugin`；若账号刚签到过或接口改版，可用 `codearts_balance` 看原始结果。 |

## 测试

```bash
bun test        # 29 个单测：签名与签名头白名单、PKCE、DPoP 验签、登录 URL、
                # 转发回归（401 复现）、额度窗口解析、签到活动选择与幂等
```

## 仓库结构

```
index.mjs                     插件本体（config / auth / loader / provider.models / auth.usage / tool）
package.json                  包元数据 + magpie 字段（maxConcurrency、options、keywords）
test/plugin.test.mjs          单测
tools/                        逆向与验证脚本（asar 读取、字符串/上下文提取、端点探测、额度与签到诊断）
docs/reverse-engineering.md   端点与协议的出处：逆向证据链
```

## 已知边界

- 「余额提醒」的落点是 magpie 的额度展示（账号卡片、`magpie quota`、`GET /v1/magpie/quotas`）——
  magpie 的插件接口没有「阈值告警」钩子（文档只定义 `auth.usage` 上报额度）。想要主动提醒，
  让 agent 调 `codearts_balance`，或开 `autoCheckin` 让每天第一次额度刷新顺带签到并回填窗口。
- 「签到」是 CodeArts 的**每日签到活动**（`USER_LOGIN` campaign，每天 1000 积分），走
  `delivery → claim → confirm`。若账号的 benefit/education 权益渠道开通了，插件也支持那条 `/api/v1/benefit/claim` 路径。
- 模型列表优先取 `statistics/plugin` 的 `model_metrics`（带启用状态），再用 agent-center 的细节补上下文长度与多模态；
  未登录时展示内置默认列表（4 个）。
- `usageTokenChatMessages` 之类的字段不是额度（例如 `package_token_amount` 为 1 却用了 1300 万 token），
  插件会跳过这类不成比例的窗口，避免给出误导数字。
- 插件只把你的请求发到 CodeArts 自己的域名，不经过任何第三方。
