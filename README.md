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
`X-Security-Token` / `X-Sdk-Date`，和 CodeArts 客户端自己的网关调用一致。

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

```bash
magpie plugin options codearts '{"channel":"benefit","autoCheckin":true}'
```

| 选项 | 默认 | 作用 |
| --- | --- | --- |
| `channel` | `benefit` | 权益渠道：`benefit` 或 `education`，也是签到时带的渠道参数 |
| `maasType` | 空 | 给推理请求加 `maas_type` 头（免费/教育权益渠道需要时填 `benefit` / `education`） |
| `autoCheckin` | `false` | 每天第一次刷新额度时自动签到一次（状态写在 magpie 配置目录的 `codearts-checkin.json`） |
| `account` | 空 | 多账号时指定工具用哪个账号（按 accountId / 用户名前缀匹配） |

## 工具

装了插件后，它们经 magpie 的内置 MCP（`http://127.0.0.1:3425/mcp/magpie/tools`）暴露给所有 agent：

- `codearts_checkin` —— 每日签到，返回领取结果与当前余额；
- `codearts_balance` —— 套餐、额度窗口、余额、到期时间；
- `codearts_welfare` —— 列出福利中心当前可领活动（只读，不自动领取）。

## 续期与登录状态

STS 凭证约 1 小时有效。插件用 `auth.refresh` 在到期前 10 分钟续一次（同一时间只续一次）。续期需要登录时
保存的 PKCE `code_verifier` 与 DPoP 私钥（ES256），它们随凭证一起存在 magpie 的 `plugin-auth.json`（权限 600）。
续期失败会返回带 `signIn: "expired"` 的错误，magpie 会把账号标记为需要重新登录。

## 测试

```bash
bun test        # 15 个单测：签名、PKCE、DPoP 验签、登录 URL、账号字段、额度窗口解析
```

## 仓库结构

```
index.mjs                     插件本体（config / auth / loader / provider.models / auth.usage / tool）
package.json                  包元数据 + magpie 字段（maxConcurrency、options、keywords）
test/plugin.test.mjs          单测
tools/                        逆向与验证脚本（asar 读取、字符串/上下文提取、端点与登录链路探针）
docs/reverse-engineering.md   端点与协议的出处：逆向证据链
```

## 已知边界

- 「余额提醒」的落点是 magpie 的额度展示（账号卡片、`magpie quota`、`GET /v1/magpie/quotas`）——
  magpie 的插件接口没有「阈值告警」钩子（文档只定义 `auth.usage` 上报额度）。想要主动提醒，
  让 agent 调 `codearts_balance`，或开 `autoCheckin` 让每天第一次额度刷新顺带签到并回填窗口。
- 「签到」对应 CodeArts 的**权益领取**（`/api/v1/benefit/claim`）；未开通权益时服务端返回
  `error_code=4000` 这类业务错误，插件会如实回报而不是伪造成功。
- 模型列表来自账号接口（内置模型 + 权益渠道模型），未登录时展示内置默认列表（4 个）。
- 额度/余额字段名取自客户端解析逻辑；接口改版时 `auth.usage` 会降级成错误文本，不影响对话转发。
- 插件只把你的请求发到 CodeArts 自己的域名，不经过任何第三方。
