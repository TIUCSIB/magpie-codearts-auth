/**
 * opencode-codearts-auth
 *
 * Magpie / OpenCode provider plugin for HUAWEI CodeArts（码道 CodeArts Doer）。
 *
 * 一个插件提供三件事：
 *   1. OAuth2 登录 —— 授权码 + PKCE + DPoP，换回华为云 STS 临时凭证（AK/SK/SecurityToken）；
 *   2. 余额提醒 —— auth.usage 钩子（magpie 的「额度」窗口 / magpie quota / GET /v1/magpie/quotas）；
 *   3. 签到 —— tool 钩子暴露 codearts_checkin（领取权益），可选按天自动签到。
 *
 * 端点与鉴权方式来自对本地 CodeArts 客户端（D:\CodeArts，app.asar\out\main\index.js 与
 * resources\bin\agent-kernel.exe）的静态分析，并用无凭据探测确认过路由存在。
 * 只从入口导出插件函数与 _internal，其余全是模块内私有函数（magpie 会把入口导出的每个
 * 函数都当成插件调用）。
 */
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// ─── 常量：与客户端 product.json / auth 配置一致 ───────────────────────────────
const PROVIDER = "codearts";
const CLIENT_ID = "codearts";
const PLUGIN_NAME = "snap_AIIDE";
const PLUGIN_VERSION = "5.1.0";
const IAM_STS_HOST = "https://sts.cn-north-4.myhuaweicloud.com";
const PORTAL_HOST = "https://codearts.huaweicloud.com/portal";
const SNAP_ENGINE = "https://snap-access.cn-north-4.myhuaweicloud.com";
const INFERHUB_BASE = `${SNAP_ENGINE}/api/v2/`;
const BENEFIT_API = "https://opengw.developer.huaweicloud.com";
const AUTH_REDIRECT_PATH = "/oauth/callback";
const LOGIN_TIMEOUT_MS = 5 * 60 * 1000;
const USER_AGENT = `opencode-codearts-auth/0.1.0`;

// 未登录 / 列表接口不可用时展示的模型（真实存在的 inferhub 模型名，登录后会被账号列表覆盖）
const DEFAULT_MODELS = {
  "GLM-5.1": { name: "GLM-5.1", context: 200000, output: 64000, reasoning: true, image: false },
  "Qwen3.6-27B-VL": { name: "Qwen3.6-27B-VL", context: 131072, output: 32768, reasoning: true, image: true },
  "maas-glm-4.7": { name: "GLM-4.7 (MaaS)", context: 131072, output: 32768, reasoning: true, image: false },
  "Qwen3-VL-235B": { name: "Qwen3-VL-235B", context: 131072, output: 32768, reasoning: true, image: true },
};

// ─── 华为云 SDK-HMAC-SHA256 签名（移植自客户端 main 进程的实现） ────────────────
function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function hmacSha256Hex(key, input) {
  return crypto.createHmac("sha256", key).update(input).digest("hex");
}

function canonicalUriOf(pathname) {
  const encoded = pathname
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
  return encoded.endsWith("/") ? encoded : `${encoded}/`;
}

function sdkDate(at = new Date()) {
  const pad = (n) => (n < 10 ? `0${n}` : String(n));
  return (
    `${at.getUTCFullYear()}${pad(at.getUTCMonth() + 1)}${pad(at.getUTCDate())}` +
    `T${pad(at.getUTCHours())}${pad(at.getUTCMinutes())}${pad(at.getUTCSeconds())}Z`
  );
}

/**
 * 返回「要真正发出的头」，其中包含 Authorization / X-Sdk-Date / host。
 * signedHeaders 里列出的头必须真的随请求发出，否则 APIG 会判定签名不合法。
 */
function signRequest({ method, url, headers = {}, body = "" }, accessKey, secretKey, at) {
  const urlObj = new URL(url);
  const canonicalQueryString = [...urlObj.searchParams.entries()]
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .sort()
    .join("&");
  const time = sdkDate(at);
  const signingHeaders = { ...headers, host: urlObj.host, "X-Sdk-Date": time };
  const entries = Object.entries(signingHeaders)
    .map(([key, value]) => ({ key: key.toLowerCase(), value: String(value).trim() }))
    .sort((a, b) => a.key.localeCompare(b.key));
  const canonicalHeaders = `${entries.map(({ key, value }) => `${key}:${value}`).join("\n")}\n`;
  const signedHeaders = entries.map(({ key }) => key).join(";");
  const canonicalRequest = [
    method.toUpperCase(),
    canonicalUriOf(urlObj.pathname),
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    sha256Hex(body),
  ].join("\n");
  const stringToSign = `SDK-HMAC-SHA256\n${time}\n${sha256Hex(canonicalRequest)}`;
  const signature = hmacSha256Hex(secretKey, stringToSign);
  return {
    ...signingHeaders,
    Authorization: `SDK-HMAC-SHA256 Access=${accessKey}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

/** 带 STS 凭据签名的一次调用。 */
async function signedFetch(auth, { method = "GET", url, body, extraHeaders = {}, signal }) {
  const payload = body === undefined ? "" : body;
  const headers = {
    "X-Security-Token": auth.securityToken,
    "Content-Type": "application/json",
    "X-Language": "zh-cn",
    "Agent-Type": "PromptCenter",
    ...extraHeaders,
  };
  const signed = signRequest({ method, url, headers, body: payload }, auth.accessKey, auth.secretKey);
  const outgoing = new Headers();
  for (const [key, value] of Object.entries(signed)) {
    // host 由传输层设置，fetch 里显式设置会被忽略/报错，签名值本身仍然匹配
    if (key.toLowerCase() === "host") continue;
    outgoing.set(key, String(value));
  }
  const res = await fetch(url, {
    method,
    headers: outgoing,
    body: method === "GET" || method === "HEAD" ? undefined : payload || undefined,
    signal,
  });
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = undefined;
  }
  return { ok: res.ok, status: res.status, data, text };
}

// ─── PKCE / DPoP ──────────────────────────────────────────────────────────────
function base64url(buffer) {
  return Buffer.from(buffer).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function generatePkcePair() {
  const codeVerifier = crypto.randomBytes(64).toString("hex");
  const codeChallenge = base64url(crypto.createHash("sha256").update(codeVerifier).digest());
  return { codeVerifier, codeChallenge };
}

async function generateDpopKeyPair() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const [privJwk, pubJwk] = await Promise.all([
    crypto.subtle.exportKey("jwk", privateKey),
    crypto.subtle.exportKey("jwk", publicKey),
  ]);
  return { privateKey: JSON.stringify(privJwk), publicKey: JSON.stringify(pubJwk) };
}

/** DPoP proof：typ=dpop+jwt，ES256，jwk=公钥，载荷 htm/htu/iat/jti。 */
async function generateDpopProof(keyPair, method, url) {
  const encoder = new TextEncoder();
  const header = { alg: "ES256", typ: "dpop+jwt", jwk: JSON.parse(keyPair.publicKey) };
  const payload = {
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomBytes(16).toString("hex"),
  };
  const signingInput = `${base64url(encoder.encode(JSON.stringify(header)))}.${base64url(encoder.encode(JSON.stringify(payload)))}`;
  const key = await crypto.subtle.importKey(
    "jwk",
    JSON.parse(keyPair.privateKey),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, encoder.encode(signingInput));
  return `${signingInput}.${base64url(signature)}`;
}

// ─── OAuth2：授权码 + PKCE + DPoP（客户端 startCallbackServer/handleCallback 的复刻） ─
function buildAuthorizeUrl({ port, codeChallenge, ticketId }) {
  const query = new URLSearchParams({
    theme: "2",
    locale: "zh-cn",
    uri_scheme: CLIENT_ID,
    client_id: CLIENT_ID,
    port: String(port),
    code_challenge: codeChallenge,
    code_challenge_method: "SHA-256",
    ticket_id: ticketId,
    "plugin-name": PLUGIN_NAME,
    "plugin-version": PLUGIN_VERSION,
  });
  return `${PORTAL_HOST}/authorize?${query.toString()}`;
}

function startCallbackServer() {
  return new Promise((resolve, reject) => {
    let settle;
    const codePromise = new Promise((res) => {
      settle = res;
    });
    const server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (url.pathname !== AUTH_REDIRECT_PATH) {
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        res.end("not found");
        return;
      }
      const code = url.searchParams.get("code");
      const error = url.searchParams.get("error");
      if (error) {
        res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
        res.end(`<h3>CodeArts 登录失败</h3><p>${error}</p>`);
        settle({ error: url.searchParams.get("error_description") || error });
        return;
      }
      if (!code) {
        res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
        res.end("<h3>未收到授权码</h3>");
        settle({ error: "未收到授权码" });
        return;
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end("<h3>CodeArts 登录成功</h3><p>可以关闭这个页面，回到 magpie。</p>");
      settle({ code });
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, port: server.address().port, codePromise });
    });
  });
}

async function exchangeToken({ code, codeVerifier, dpopKeyPair, port }) {
  const url = `${IAM_STS_HOST}/v1/oauth2/tokens`;
  const dpop = await generateDpopProof(dpopKeyPair, "POST", url);
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    code,
    code_verifier: codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: `http://127.0.0.1:${port}${AUTH_REDIRECT_PATH}`,
  }).toString();
  const res = await fetch(url, {
    method: "POST",
    headers: { DPoP: dpop, "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  const data = await res.json().catch(() => undefined);
  if (!res.ok) {
    const message = data?.error?.message || data?.error_description || `HTTP ${res.status}`;
    throw Object.assign(new Error(`CodeArts token exchange failed: ${message}`), { signIn: "expired" });
  }
  return data;
}

async function refreshAccessToken({ refreshToken, codeVerifier, dpopKeyPair }) {
  const url = `${IAM_STS_HOST}/v1/oauth2/tokens`;
  const dpop = await generateDpopProof(dpopKeyPair, "POST", url);
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    code_verifier: codeVerifier,
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  }).toString();
  const res = await fetch(url, {
    method: "POST",
    headers: { DPoP: dpop, "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  const data = await res.json().catch(() => undefined);
  if (!res.ok) {
    const message = data?.error?.message || data?.error_description || `HTTP ${res.status}`;
    throw Object.assign(new Error(`CodeArts token refresh failed: ${message}`), { signIn: "expired" });
  }
  return data;
}

/** 把 token 响应折叠成 magpie 账号字段（额外字段 magpie 会一起保存）。 */
function sessionFromTokenResponse(tokenResponse, extra = {}) {
  const credentials = tokenResponse?.credentials;
  if (!credentials) throw Object.assign(new Error("CodeArts 返回里没有 credentials"), { signIn: "expired" });
  return {
    access: credentials.security_token,
    refresh: tokenResponse.refresh_token,
    expires: credentials.expiration ? new Date(credentials.expiration).getTime() : Date.now() + 55 * 60 * 1000,
    accessKey: credentials.access_key_id,
    secretKey: credentials.secret_access_key,
    securityToken: credentials.security_token,
    ...extra,
  };
}

/** GET /v5/caller-identity：拿华为云账号名，用来给 magpie 的账号命名。 */
async function fetchCallerIdentity(auth) {
  const url = `${IAM_STS_HOST}/v5/caller-identity`;
  const res = await signedFetch(auth, { method: "GET", url });
  const data = res.data;
  if (!data) return {};
  const urn = typeof data.principal_urn === "string" ? data.principal_urn : "";
  let userName = urn ? urn.substring(urn.lastIndexOf(":") + 1) : "";
  if (userName.includes("/")) userName = userName.substring(userName.indexOf("/") + 1);
  return {
    userName: userName || data.user_name || data.userName || "",
    userId: data.principal_id || data.user_id || data.userId || "",
    domainId: data.account_id || data.domain_id || data.domainId || "",
  };
}

// ─── 业务端点 ─────────────────────────────────────────────────────────────────
const firstOf = (...values) => values.find((v) => v !== undefined && v !== null && v !== "");
const num = (value) => {
  const n = typeof value === "string" ? Number(value) : value;
  return Number.isFinite(n) ? n : undefined;
};

/** 余额：GET {benefit}/api/v1/user/tokens/balance */
async function fetchBalance(auth, channel) {
  const base = `${BENEFIT_API}/api/v1/user/tokens/balance`;
  const url = channel ? `${base}?channel=${encodeURIComponent(channel)}` : base;
  const res = await signedFetch(auth, { method: "GET", url, signal: undefined });
  if (res.data?.error_code && res.data.error_code !== "0000") {
    return { error: `余额接口返回 error_code=${res.data.error_code}` };
  }
  const result = res.data?.result ?? res.data;
  const tokens = firstOf(num(result?.available_tokens), num(result?.remain_tokens), num(result?.balance), num(result?.tokens), num(result?.total));
  return { raw: result, tokens };
}

/** 套餐概览：GET {snap}/snap-manager/v1/package/overview —— 「余额/额度」的主来源。 */
async function fetchPackageOverview(auth) {
  const url = `${SNAP_ENGINE}/snap-manager/v1/package/overview`;
  const res = await signedFetch(auth, { method: "GET", url, extraHeaders: {} });
  return res.data;
}

function packageWindows(overview) {
  const metrics = Array.isArray(overview?.metrics) ? overview.metrics : [];
  const windows = [];
  for (const metric of metrics) {
    const name = metric?.name;
    if (!name) continue;
    if (metric.show === false) continue;
    const used = num(metric.package_credit_used);
    const amount = num(metric.package_credit_amount);
    const remain = num(metric.package_credit_remain);
    const expiring = num(metric.package_credit_expiring_amount);
    const usedTokens = num(metric.usage_token_num);
    const tokenAmount = num(metric.package_token_amount);
    const isUnlimited = usedTokens === -1 || tokenAmount === -1;
    const display = isUnlimited
      ? "不限量"
      : amount !== undefined
        ? `${used ?? 0} / ${amount} credits（剩余 ${remain ?? amount - (used ?? 0)}${expiring ? `，${expiring} 即将过期` : ""}）`
        : tokenAmount !== undefined
          ? `${usedTokens ?? 0} / ${tokenAmount} tokens`
          : undefined;
    const percent = amount && amount > 0 && used !== undefined
      ? (used * 100) / amount
      : tokenAmount && tokenAmount > 0 && usedTokens !== undefined
        ? (usedTokens * 100) / tokenAmount
        : undefined;
    windows.push({
      name,
      used: percent,
      amount: amount ?? usedTokens,
      limit: amount ?? tokenAmount,
      unit: amount !== undefined ? "credits" : "tokens",
      display,
      aside: metric.show === false,
    });
  }
  return windows;
}

/** 权益渠道开关：GET {policyCenter}/v1/{benefit|education}-gateway-config */
async function fetchGatewayEnabled(auth, channel) {
  const suffix = channel === "education" ? "education-gateway-config" : "benefit-gateway-config";
  const res = await signedFetch(auth, { method: "GET", url: `${SNAP_ENGINE}/v1/${suffix}` });
  const enabled = res.data?.enabled ?? res.data?.result?.enabled ?? false;
  return Boolean(enabled);
}

/** 免费/教育权益渠道的模型列表：GET {benefit}/api/v1/gateway/config[?channel=education] */
async function fetchChannelModels(auth, channel) {
  const params = channel && channel !== "benefit" ? `?channel=${encodeURIComponent(channel)}` : "";
  const res = await signedFetch(auth, { method: "GET", url: `${BENEFIT_API}/api/v1/gateway/config${params}` });
  const models = res.data?.result?.models;
  if (res.data?.error_code !== "0000" || !Array.isArray(models)) return [];
  return models.map((model) => ({
    id: model.model_id || model.modelId,
    name: model.model_name || model.modelName || model.model_id,
    context: num(model.context_window),
    output: num(model.max_tokens),
    free: true,
    channel,
  })).filter((m) => m.id);
}

/** 内置 inferhub 模型：先找 CodeAgent，再读它的 gpts.models。 */
async function fetchBuiltinModels(auth) {
  const listUrl = `${SNAP_ENGINE}/v1/agent-center/agents/useragents?offset=0&limit=100&is_primary_agent=true`;
  const list = await signedFetch(auth, {
    method: "GET",
    url: listUrl,
    extraHeaders: { "Agent-Type": "AgentCenter" },
  });
  const agents = list.data?.agents ?? [];
  const agent =
    agents.find((item) => item?.agent_name === "CodeAgent" && item?.show_in_ide) ??
    agents.find((item) => item?.agent_name === "CodeAgent") ??
    agents[0];
  if (!agent?.agent_id) return [];
  const detailUrl = `${SNAP_ENGINE}/v1/agent-center/agents/detail?agent_id=${encodeURIComponent(agent.agent_id)}`;
  const detail = await signedFetch(auth, {
    method: "GET",
    url: detailUrl,
    extraHeaders: { "Agent-Type": "AgentCenter" },
  });
  const models = detail.data?.gpts?.models;
  if (!Array.isArray(models)) return [];
  return models
    .filter((model) => model?.model_type !== "third")
    .map((model) => {
      const params = model.model_parameters ?? {};
      return {
        id: params.model_id || model.model_name,
        name: model.model_name || params.model_id,
        context: num(params.context_window) ?? num(params.max_context_tokens),
        output: num(params.max_tokens),
        image: Boolean(params.supports_images),
        reasoning: Boolean(model.think_level) || undefined,
        custom: model.model_type === "custom",
      };
    })
    .filter((m) => m.id);
}

/** 签到 / 领取权益：POST {benefit}/api/v1/benefit/claim[?channel=…] */
async function claimBenefit(auth, channel) {
  const base = `${BENEFIT_API}/api/v1/benefit/claim`;
  const url = channel ? `${base}?channel=${encodeURIComponent(channel)}` : base;
  const res = await signedFetch(auth, { method: "POST", url, body: "{}" });
  const data = res.data;
  const code = data?.error_code;
  const ok = code === "0000" || code === undefined || code === 0;
  return {
    ok,
    errorCode: code,
    message: data?.error_msg || data?.message,
    result: data?.result,
  };
}

/** 福利活动列表：GET {policyCenter}/v1/ops/delivery?channel=DESKTOP */
async function fetchWelfareDelivery(auth) {
  const url = `${SNAP_ENGINE}/v1/ops/delivery?channel=DESKTOP`;
  const res = await signedFetch(auth, {
    method: "GET",
    url,
    extraHeaders: { "x-snap-traceid": crypto.randomUUID() },
  });
  const data = res.data;
  const ok = data?.code === 0 || data?.code === 200 || data?.data !== undefined || data?.success === true;
  return { ok, data: data?.data ?? data };
}

// ─── 签到状态（按天一次）────────────────────────────────────────────────────────
function checkinStateFile(directory) {
  return path.join(directory || process.cwd(), "codearts-checkin.json");
}

function readCheckinState(directory) {
  try {
    return JSON.parse(fs.readFileSync(checkinStateFile(directory), "utf8"));
  } catch {
    return {};
  }
}

function writeCheckinState(directory, state) {
  try {
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(checkinStateFile(directory), JSON.stringify(state, null, 2));
  } catch {
    /* 状态文件只是加速缓存，写不进去也不影响签到 */
  }
}

const today = () => new Date().toISOString().slice(0, 10);

// ─── 插件 ─────────────────────────────────────────────────────────────────────
export const CodeArtsAuthPlugin = async ({ directory }, pluginOptions) => {
  // magpie 会把插件函数第二个参数（plugins.json 里这一项的 options）传进来；
  // 拿不到时回落到配置文件，最后用默认值。
  const defaults = { channel: "benefit", maasType: "", autoCheckin: false, account: "" };
  const options = { ...defaults };
  let optionsLoaded = false;
  const getOptions = async () => {
    if (optionsLoaded) return options;
    optionsLoaded = true;
    if (pluginOptions && typeof pluginOptions === "object") Object.assign(options, pluginOptions);
    try {
      const cfg = JSON.parse(fs.readFileSync(path.join(directory, "plugins.json"), "utf8"));
      const entry = (cfg.plugins ?? []).find((item) => String(item.spec ?? "").includes("codearts-auth"));
      if (entry?.options) Object.assign(options, entry.options);
    } catch {
      /* 选项缺失时用默认值 */
    }
    return options;
  };

  // magpie 的 tool 钩子拿不到账号，所以把 loader / usage / refresh 见过的账号记下来。
  const accounts = new Map();
  const remember = (auth) => {
    if (!auth || auth.type !== "oauth" || !auth.accessKey) return auth;
    const key = auth.accountId || auth.userName || auth.userId || auth.accessKey;
    accounts.set(key, auth);
    return auth;
  };
  const accountOf = async (getAuth) => remember(typeof getAuth === "function" ? await getAuth() : getAuth);

  /** 工具用：按选项指定账号，否则用最近见过的那个账号。 */
  const resolveAccount = async () => {
    const opts = await getOptions();
    if (opts.account && accounts.has(opts.account)) return accounts.get(opts.account);
    if (opts.account) {
      for (const [key, auth] of accounts) {
        if (key.startsWith(opts.account) || auth.userName === opts.account) return auth;
      }
    }
    const list = [...accounts.values()];
    return list[list.length - 1];
  };

  return {
    // 供应商声明：magpie 未登录时也能列出这些模型
    async config(cfg) {
      cfg.provider ??= {};
      cfg.provider[PROVIDER] ??= {
        name: "CodeArts (码道)",
        npm: "@ai-sdk/openai-compatible",
        api: INFERHUB_BASE,
        models: Object.fromEntries(
          Object.entries(DEFAULT_MODELS).map(([id, model]) => [
            id,
            {
              name: model.name,
              limit: { context: model.context, output: model.output },
              reasoning: model.reasoning,
              tool_call: true,
              modalities: { input: model.image ? ["text", "image"] : ["text"] },
            },
          ]),
        ),
      };
    },

    auth: {
      provider: PROVIDER,
      // 提前 10 分钟续期：STS 凭证默认 1 小时，magpie 只会在 expires 临近时续一次
      refreshLead: 10 * 60 * 1000,
      methods: [
        {
          type: "oauth",
          label: "Sign in with HUAWEI CodeArts",
          async authorize() {
            const pkcePair = generatePkcePair();
            const dpopKeyPair = await generateDpopKeyPair();
            const { server, port, codePromise } = await startCallbackServer();
            const ticketId = crypto.randomBytes(32).toString("hex");
            const url = buildAuthorizeUrl({ port, codeChallenge: pkcePair.codeChallenge, ticketId });

            let closed = false;
            const shutdown = () => {
              if (closed) return;
              closed = true;
              try {
                server.close();
              } catch {
                /* ignore */
              }
            };

            return {
              url,
              instructions:
                "在浏览器里用华为云账号登录 CodeArts（码道）。登录完成后本页会提示成功，可以关闭它。",
              method: "auto",
              async callback() {
                try {
                  const timeout = new Promise((resolve) => {
                    setTimeout(() => resolve({ error: "登录超时（5 分钟）" }), LOGIN_TIMEOUT_MS);
                  });
                  const outcome = await Promise.race([codePromise, timeout]);
                  if (!outcome?.code) {
                    return { type: "failed", error: outcome?.error || "登录被取消" };
                  }
                  const tokenResponse = await exchangeToken({
                    code: outcome.code,
                    codeVerifier: pkcePair.codeVerifier,
                    dpopKeyPair,
                    port,
                  });
                  const session = sessionFromTokenResponse(tokenResponse, {
                    codeVerifier: pkcePair.codeVerifier,
                    dpopPrivate: dpopKeyPair.privateKey,
                    dpopPublic: dpopKeyPair.publicKey,
                    clientId: CLIENT_ID,
                  });
                  let identity = {};
                  try {
                    identity = await fetchCallerIdentity(session);
                  } catch {
                    /* 账号名拿不到不影响登录 */
                  }
                  return {
                    type: "success",
                    ...session,
                    ...identity,
                    accountId: identity.userName || identity.userId || session.accessKey,
                  };
                } catch (error) {
                  return { type: "failed", error: String(error?.message ?? error).slice(0, 500) };
                } finally {
                  shutdown();
                }
              },
            };
          },
        },
        {
          // 允许把 CodeArts 客户端的 x-auth-token 直接当密钥用（没有 STS 凭证时）
          type: "api",
          label: "CodeArts x-auth-token",
          placeholder: "x-auth-token（可选：华为云 IAM token）",
        },
      ],

      /** 续期：magpie 在 expires 之前调用一次，成功即刷新标记。 */
      async refresh(auth) {
        remember(auth);
        if (!auth?.refresh || !auth?.codeVerifier || !auth?.dpopPrivate) {
          throw Object.assign(new Error("CodeArts 账号缺少续期所需字段，请重新登录"), { signIn: "expired" });
        }
        const tokenResponse = await refreshAccessToken({
          refreshToken: auth.refresh,
          codeVerifier: auth.codeVerifier,
          dpopKeyPair: { privateKey: auth.dpopPrivate, publicKey: auth.dpopPublic },
        });
        return sessionFromTokenResponse(tokenResponse, {
          codeVerifier: auth.codeVerifier,
          dpopPrivate: auth.dpopPrivate,
          dpopPublic: auth.dpopPublic,
          clientId: CLIENT_ID,
          userName: auth.userName,
          userId: auth.userId,
          domainId: auth.domainId,
        });
      },

      /** 每个请求：签名后转发到 inferhub 的 OpenAI 兼容端点。 */
      async loader(getAuth) {
        const auth = remember(await getAuth());
        const opts = await getOptions();
        if (auth?.type === "api" && auth?.key) {
          return {
            baseURL: INFERHUB_BASE,
            async fetch(input, init) {
              const headers = new Headers(init?.headers);
              headers.set("x-auth-token", auth.key);
              if (opts.maasType) headers.set("maas_type", opts.maasType);
              headers.set("x-ot-client-type", "opencode-codearts-auth");
              headers.set("x-ot-client-version", "0.1.0");
              return fetch(input, { ...init, headers });
            },
          };
        }
        if (auth?.type !== "oauth" || !auth?.accessKey) return {};

        return {
          baseURL: INFERHUB_BASE,
          async fetch(input, init) {
            const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
            const method = init?.method ?? "GET";
            const rawBody = init?.body;
            let body = "";
            if (typeof rawBody === "string") {
              body = rawBody;
            } else if (rawBody instanceof Uint8Array || rawBody instanceof ArrayBuffer) {
              body = Buffer.from(rawBody).toString("utf8");
            }
            const headers = new Headers(init?.headers);
            headers.set("x-ot-client-type", "opencode-codearts-auth");
            headers.set("x-ot-client-version", "0.1.0");
            headers.set("plugin-name", PLUGIN_NAME);
            headers.set("plugin-version", PLUGIN_VERSION);
            if (opts.maasType) headers.set("maas_type", opts.maasType);
            const signed = signRequest(
              {
                method,
                url,
                headers: Object.fromEntries(headers.entries()),
                body,
              },
              auth.accessKey,
              auth.secretKey,
            );
            for (const [key, value] of Object.entries(signed)) {
              if (key.toLowerCase() === "host") continue;
              headers.set(key, String(value));
            }
            return fetch(input, { ...init, headers });
          },
        };
      },

      /** 余额提醒：magpie 的账号额度窗口 / magpie quota / GET /v1/magpie/quotas。 */
      async usage(getAuth) {
        const auth = await accountOf(getAuth);
        if (!auth?.accessKey) return { windows: [], error: "请先登录 CodeArts" };
        const opts = await getOptions();
        const result = { windows: [] };
        let failed = false;

        try {
          const overview = await fetchPackageOverview(auth);
          if (overview) {
            const pkg = overview.package ?? {};
            result.plan = pkg.package_name_cn || pkg.package_name_en || undefined;
            result.until = overview.end_date || undefined;
            result.windows.push(...packageWindows(overview));
            const onDemand = (overview.model_package ?? []).reduce(
              (sum, item) => sum + (num(item?.package_user_used_token) ?? 0),
              0,
            );
            if (onDemand > 0) {
              result.windows.push({
                name: "按需用量",
                amount: onDemand,
                unit: "tokens",
                display: `${onDemand} tokens（按量计费部分）`,
              });
            }
          }
        } catch (error) {
          failed = true;
          result.error = `套餐概览读取失败：${String(error?.message ?? error)}`;
        }

        try {
          const balance = await fetchBalance(auth, opts.channel);
          if (balance.error) {
            if (!result.error) result.error = balance.error;
          } else if (balance.tokens !== undefined) {
            result.balance = `${balance.tokens} tokens`;
          }
        } catch (error) {
          failed = true;
          if (!result.error) result.error = `余额读取失败：${String(error?.message ?? error)}`;
        }

        // 可选：让 magpie 的定期额度刷新顺带完成当天签到
        if (opts.autoCheckin) {
          const state = readCheckinState(directory);
          if (state.lastCheckin !== today()) {
            try {
              const claimed = await claimBenefit(auth, opts.channel);
              state.lastCheckin = today();
              state.lastResult = claimed.ok ? "ok" : String(claimed.errorCode ?? claimed.message ?? "failed");
              writeCheckinState(directory, state);
              if (claimed.ok) {
                result.windows.push({ name: "今日签到", display: "已领取权益 ✅" });
              }
            } catch (error) {
              state.lastCheckin = today();
              state.lastResult = String(error?.message ?? error);
              writeCheckinState(directory, state);
            }
          }
        }

        if (failed && result.windows.length === 0) return result;
        return result;
      },
    },

    /** 账号自己的模型列表：权益渠道 + 内置 inferhub 模型。 */
    provider: {
      id: PROVIDER,
      async models(provider, { auth } = {}) {
        if (auth?.type !== "oauth" || !auth?.accessKey) return provider.models;
        let found = [];
        try {
          found = await fetchBuiltinModels(auth);
        } catch {
          found = [];
        }
        try {
          if (await fetchGatewayEnabled(auth, "benefit")) {
            found = [...found, ...(await fetchChannelModels(auth, "benefit"))];
          }
          if (await fetchGatewayEnabled(auth, "education")) {
            found = [...found, ...(await fetchChannelModels(auth, "education"))];
          }
        } catch {
          /* 权益渠道不可用时只用内置模型 */
        }
        if (found.length === 0) return provider.models;
        const template = Object.values(provider.models)[0] ?? {};
        const seen = new Set();
        const models = {};
        for (const model of found) {
          if (!model.id || seen.has(model.id)) continue;
          seen.add(model.id);
          models[model.id] = {
            ...template,
            id: model.id,
            name: model.name ?? model.id,
            limit: {
              context: model.context ?? template.limit?.context ?? 128000,
              output: model.output ?? template.limit?.output ?? 32000,
            },
            capabilities: {
              reasoning: Boolean(model.reasoning),
              toolcall: true,
              attachment: Boolean(model.image),
              input: { text: true, image: Boolean(model.image) },
            },
            ...(model.free ? { free: true } : {}),
          };
        }
        return models;
      },
    },

    /** 每个请求带上渠道标识（免费权益渠道需要 maas_type / benefit）。 */
    "chat.headers": async (input, output) => {
      const opts = await getOptions();
      if (input?.model?.providerID !== PROVIDER) return;
      if (opts.maasType) output.headers["maas_type"] = opts.maasType;
      output.headers["x-ot-client-type"] = "opencode-codearts-auth";
      output.headers["x-ot-client-version"] = "0.1.0";
    },

    /** 签到相关工具，经 magpie 的内置 MCP（/mcp/magpie/tools）给任意 agent。 */
    tool: {
      checkin: {
        description: "CodeArts 每日签到：领取当日免费权益/额度，并返回当前余额。",
        args: {
          type: "object",
          properties: {
            channel: { type: "string", description: "权益渠道：benefit（默认）或 education" },
          },
          additionalProperties: false,
        },
        async execute(args = {}, ctx) {
          const auth = await resolveAccount();
          if (!auth?.accessKey) return "未登录 CodeArts，请先在 magpie 里登录该供应商。";
          const opts = await getOptions();
          const channel = args.channel || opts.channel;
          const claimed = await claimBenefit(auth, channel);
          const state = readCheckinState(directory);
          state.lastCheckin = today();
          state.lastResult = claimed.ok ? "ok" : String(claimed.errorCode ?? claimed.message ?? "failed");
          writeCheckinState(directory, state);
          const lines = [
            claimed.ok
              ? `✅ 签到成功${claimed.result ? `：${JSON.stringify(claimed.result)}` : ""}`
              : `⚠️ 签到未成功：error_code=${claimed.errorCode ?? "unknown"}${claimed.message ? ` ${claimed.message}` : ""}`,
          ];
          try {
            const balance = await fetchBalance(auth, channel);
            if (balance.tokens !== undefined) lines.push(`当前余额：${balance.tokens} tokens`);
          } catch {
            /* 余额读不到就只回签到结果 */
          }
          lines.push(`（渠道：${channel ?? "benefit"}，日期：${today()}）`);
          return lines.join("\n");
        },
      },
      balance: {
        description: "查询 CodeArts 账号余额、套餐额度与到期时间。",
        args: {
          type: "object",
          properties: {
            channel: { type: "string", description: "权益渠道：benefit（默认）或 education" },
          },
          additionalProperties: false,
        },
        async execute(args = {}, ctx) {
          const auth = await resolveAccount();
          if (!auth?.accessKey) return "未登录 CodeArts，请先在 magpie 里登录该供应商。";
          const opts = await getOptions();
          const channel = args.channel || opts.channel;
          const lines = [];
          try {
            const overview = await fetchPackageOverview(auth);
            const pkg = overview?.package ?? {};
            lines.push(`套餐：${pkg.package_name_cn || pkg.package_name_en || "未知"}${overview?.end_date ? `（到期 ${overview.end_date}）` : ""}`);
            for (const window of packageWindows(overview)) {
              lines.push(`· ${window.name}：${window.display ?? `${window.used ?? 0}%`}`);
            }
          } catch (error) {
            lines.push(`套餐概览读取失败：${String(error?.message ?? error)}`);
          }
          try {
            const balance = await fetchBalance(auth, channel);
            lines.push(balance.tokens !== undefined ? `余额：${balance.tokens} tokens` : `余额：${balance.error ?? "接口未返回可读字段"}`);
          } catch (error) {
            lines.push(`余额读取失败：${String(error?.message ?? error)}`);
          }
          return lines.join("\n");
        },
      },
      welfare: {
        description: "查看 CodeArts 福利中心当前可领取的活动（不自动领取）。",
        args: { type: "object", properties: {}, additionalProperties: false },
        async execute(_args, ctx) {
          const auth = await resolveAccount();
          if (!auth?.accessKey) return "未登录 CodeArts，请先在 magpie 里登录该供应商。";
          const delivery = await fetchWelfareDelivery(auth);
          if (!delivery.ok) return `福利接口返回异常：${JSON.stringify(delivery.data).slice(0, 400)}`;
          return `福利活动：${JSON.stringify(delivery.data).slice(0, 1500)}`;
        },
      },
    },
  };
};

/** 测试入口：magpie 只调用函数导出，所以辅助函数放在这里。 */
export const _internal = {
  PROVIDER,
  INFERHUB_BASE,
  IAM_STS_HOST,
  PORTAL_HOST,
  BENEFIT_API,
  SNAP_ENGINE,
  signRequest,
  canonicalUriOf,
  sdkDate,
  sha256Hex,
  generatePkcePair,
  generateDpopProof,
  generateDpopKeyPair,
  buildAuthorizeUrl,
  sessionFromTokenResponse,
  packageWindows,
  DEFAULT_MODELS,
};
