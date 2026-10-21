# opencode-codearts-auth

Magpie（usemagpie.ai）供应商插件：用你的华为云 **CodeArts（码道）** 账号登录，把 CodeArts 的
inferhub 模型接进 magpie，于是 Claude Code / Codex / OpenCode / Gemini CLI 等所有 agent 都能用；
同时提供**余额提醒**和**每日签到**。

- **登录方式**：OAuth2 授权码 + PKCE + DPoP（与 CodeArts 桌面客户端同一条登录链路），换回华为云 STS
  临时凭证（AK/SK/SecurityToken）；也支持直接填 `x-auth-token`。
- **余额提醒**：`auth.usage` 钩子把套餐额度、剩余 credits/tokens、到期时间报到 magpie 的账号额度窗口、
  `magpie quota` 和 `GET /v1/magpie/quotas`。
- **签到**：工具 `codearts_checkin`（领取当日权益并回读余额），可开启每天自动签到一次。

## 安装

```bash
magpie plugin add ./opencode-codearts-auth        # 或发布后的包名
magpie plugin login codearts                      # 选 “Sign in with HUAWEI CodeArts”
magpie plugin                                      # codearts (CodeArts (码道), 4 models)  signed in
magpie provider test codearts                      # 打通一个最小请求
magpie quota                                       # 看余额 / 额度窗口
```

应用里：插件 → 添加插件 → 填文件夹路径 → 在 `codearts` 这一行点登录，浏览器里用华为云账号完成授权。

登录成功后 agent 用 `codearts/GLM-5.1` 这样引用模型，和其它供应商一样。

## 端点与鉴权（逆向自客户端）

所有请求都带华为云 `SDK-HMAC-SHA256` 签名（`Authorization: SDK-HMAC-SHA256 Access=…`）与
`X-Security-Token` / `X-Sdk-Date`，与 CodeArts 桌面客户端自己的网关调用一致。

| 用途 | 方法与端点 |
| --- | --- |
| 授权页 | `GET https://codearts.huaweicloud.com/portal/authorize?client_id=codearts&port=<本地端口>&code_challenge=…&ticket_id=…&plugin-name=snap_AIIDE&plugin-version=5.1.0` |
| 换 token / 续期 | `POST https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens`（`authorization_code` / `refresh_token`，带 `DPoP` 头） |
| 账号信息 | `GET https://sts.cn-north-4.myhuaweicloud.com/v5/caller-identity` |
| **推理（OpenAI 兼容）** | `POST https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions` |
| 余额 | `GET https://opengw.developer.huaweicloud.com/api/v1/user/tokens/balance[?channel=benefit]` |
| **签到 / 领取权益** | `POST https://opengw.developer.huaweicloud.com/api/v1/benefit/claim[?channel=benefit]` |
| 套餐额度概览 | `GET https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager/v1/package/overview` |
| 权益渠道开关 | `GET https://snap-access.cn-north-4.myhuaweicloud.com/v1/{benefit,education}-gateway-config` |
| 渠道模型列表 | `GET https://opengw.developer.huaweicloud.com/api/v1/gateway/config[?channel=education]` |
| 福利活动 | `GET https://snap-access.cn-north-4.myhuaweicloud.com/v1/ops/delivery?channel=DESKTOP` |

返回体约定：多数接口是 `{ "error_code": "0000", "result": … }`；`/v1/ops/*` 用 `{ code, data }`。

## 插件选项

`magpie plugin options codearts '{"channel":"benefit","autoCheckin":true}'`，或在插件页那一行编辑 JSON。

| 选项 | 默认 | 作用 |
| --- | --- | --- |
| `channel` | `benefit` | 权益渠道：`benefit` 或 `education`，也是签到时带的渠道参数 |
| `maasType` | 空 | 给推理请求加 `maas_type` 头（免费/教育权益渠道需要时填 `benefit` / `education`） |
| `autoCheckin` | `false` | 每天第一次刷新额度时自动签到一次（状态写在 magpie 配置目录的 `codearts-checkin.json`） |

## 工具

装了插件后，它们经 magpie 内置 MCP（`http://127.0.0.1:3425/mcp/magpie/tools`）暴露给所有 agent：

- `codearts_checkin` —— 每日签到，返回领取结果与当前余额；
- `codearts_balance` —— 套餐、额度窗口、余额、到期时间；
- `codearts_welfare` —— 列出福利中心当前可领活动（只读，不自动领取）。

## 续期与登录状态

STS 凭证默认 55 分钟~1 小时。插件用 `auth.refresh` 在到期前 10 分钟续一次（同一时间只续一次）；
续期需要登录时保存的 PKCE `code_verifier` 与 DPoP 私钥（ES256），插件把它们连同凭证一起存在 magpie 的
`plugin-auth.json`（权限 600）。续期失败会返回带 `signIn: "expired"` 的错误，magpie 会把账号标记为需要重新登录。

## 测试

```bash
bun test          # 15 个单测：签名、PKCE、DPoP 验签、登录 URL、账号字段、额度窗口解析
```

## 已知边界

- 模型列表来自账号接口（内置 inferhub 模型 + 权益渠道模型），未登录时展示内置的默认列表（4 个）。
- 额度窗口的字段名按客户端解析逻辑映射；接口若改版，`usage` 会降级为 `error` 文本而不影响对话。
- `x-auth-token` 登录方式只在你有 IAM token 时使用；正常走 OAuth。
- 插件只把你的请求发到 CodeArts 自己的域名，不经过任何第三方。
