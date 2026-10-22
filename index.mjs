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

// 未登录 / 列表接口不可用时展示的模型：全部取自账号侧 statistics/plugin 的 model_metrics，
// 不要放账号里没有的 id —— 选了不存在的模型，服务端会回 404 "The model is not registered"。
const DEFAULT_MODELS = {
  "GLM-5.2": { name: "GLM-5.2", context: 200000, output: 64000, reasoning: true, image: false },
  "glm-5.3": { name: "GLM-5.3", context: 200000, output: 64000, reasoning: true, image: false },
  "deepseek-v4.1-flash": { name: "DeepSeek-V4.1-Flash", context: 128000, output: 32000, reasoning: true, image: false },
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

// 只有这些头参与签名。别的头（accept、accept-encoding、user-agent、authorization…）
// 由传输层/框架自己处理，一旦纳入签名就会在发送时被改写，导致服务端验签失败
// （APIG 会回 401 "verify ak sk signature fail"）。
const SIGNED_HEADERS = [
  "content-type",
  "x-security-token",
  "x-language",
  "plugin-name",
  "plugin-version",
  "x-ot-client-type",
  "x-ot-client-version",
  "maas_type",
  "agent-type",
];

// CodeArts 服务端限制「同时进行的会话数」（默认 3）。magpie 的账号并发如果设得比它高，
// 或者同一时刻有别的客户端/agent 在说话，多余的那个请求就会拿到这个业务码。
const SESSION_LIMIT_CODE = "TM.00001041";

const sleep = (ms, signal) =>
  new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason ?? new Error("aborted"));
    const timer = setTimeout(() => {
      signal?.removeEventListener?.("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal.reason ?? new Error("aborted"));
    };
    signal?.addEventListener?.("abort", onAbort, { once: true });
  });

/** 400 + TM.00001041：并发会话满了。读的是克隆体，原响应仍然可以照常流式返回。 */
async function isSessionLimit(response) {
  if (response.status !== 400) return false;
  try {
    return (await response.clone().text()).includes(SESSION_LIMIT_CODE);
  } catch {
    return false;
  }
}

// 按账号的「在飞请求」计数：CodeArts 的并发会话上限是账号级的，插件必须自己排队。
const inflight = new Map();

function slotKeyOf(auth) {
  return auth?.accountId || auth?.userName || auth?.userId || auth?.accessKey || "codearts";
}

function slotState(key) {
  let state = inflight.get(key);
  if (!state) {
    state = { active: 0, queue: [] };
    inflight.set(key, state);
  }
  return state;
}

/** 拿一个并发位；返回的函数负责归还。排队中被取消会直接抛错。 */
async function acquireSlot(key, limit, signal) {
  const state = slotState(key);
  const release = () => {
    state.active = Math.max(0, state.active - 1);
    const next = state.queue.shift();
    if (next) next();
  };

  if (state.active < limit) {
    state.active += 1;
    return release;
  }

  await new Promise((resolve, reject) => {
    const waiter = () => {
      if (signal && onAbort) signal.removeEventListener("abort", onAbort);
      resolve();
    };
    const onAbort = signal
      ? () => {
          const index = state.queue.indexOf(waiter);
          if (index >= 0) state.queue.splice(index, 1);
          reject(signal.reason ?? new Error("aborted"));
        }
      : undefined;
    if (onAbort) signal.addEventListener("abort", onAbort, { once: true });
    state.queue.push(waiter);
  });

  state.active += 1;
  return release;
}

/**
 * 响应被 magpie 读完（或读取方取消、请求被 abort）之后才归还并发位。
 * 流式答复如果不这样做，下一个请求会在线路还热的时候挤进来，又变成一个服务端会话。
 */
function holdSlotUntilBodyEnds(response, release, signal) {
  if (!response.body) {
    release();
    return response;
  }
  let done = false;
  let guard;
  const finish = () => {
    if (done) return;
    done = true;
    if (guard) clearTimeout(guard);
    signal?.removeEventListener?.("abort", finish);
    release();
  };
  // 兜底：万一读取方既不读完也不取消（或者 body 被丢弃），别把这个账号永久锁死
  guard = setTimeout(finish, 5 * 60 * 1000);
  guard?.unref?.();
  signal?.addEventListener?.("abort", finish, { once: true });
  const body = response.body.pipeThrough(
    new TransformStream({
      transform(chunk, controller) {
        controller.enqueue(chunk);
      },
      flush() {
        finish();
      },
    }),
  );
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

/** 重试仍然被并发上限挡住时，把可操作的说明并进错误信息（保留原有字段，各 agent 仍能解析）。 */
async function annotateSessionLimit(response, attempts) {
  const text = await response.text();
  const hint =
    `（magpie 已重试 ${attempts} 次。CodeArts 按账号限制同时活跃的会话数为 3，` +
    `名额由服务端自己回收，客户端每次启动也会占一个；请稍等几分钟重试，` +
    `并把 magpie 里这个账号的「并发」设在 2 以下、不要同时开着多个对话。）`;
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = undefined;
  }
  const merged =
    payload && typeof payload === "object"
      ? { ...payload, error_msg: `${payload.error_msg ?? ""} ${hint}`.trim() }
      : { error_code: SESSION_LIMIT_CODE, error_msg: `${text} ${hint}`.trim() };
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  headers.set("content-type", "application/json");
  return new Response(JSON.stringify(merged), {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/** 把 AI SDK 的请求签名后转发到 inferhub；遇到并发上限时短退避重试。 */
async function forwardSigned(auth, opts, input, init) {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const method = init?.method ?? "GET";
  const rawBody = init?.body;
  let body = "";
  if (typeof rawBody === "string") {
    body = rawBody;
  } else if (rawBody instanceof Uint8Array) {
    body = Buffer.from(rawBody).toString("utf8");
  } else if (rawBody instanceof ArrayBuffer) {
    body = Buffer.from(new Uint8Array(rawBody)).toString("utf8");
  }

  const headers = new Headers(init?.headers);
  // 这两个头会改变 APIG 的鉴权判定，必须由我们接管
  headers.delete("authorization");
  headers.delete("x-auth-token");
  headers.delete("host");
  headers.delete("content-length");
  if (!headers.has("content-type")) headers.set("content-type", "application/json");
  headers.set("x-security-token", auth.securityToken);
  headers.set("x-language", "zh-cn");
  headers.set("plugin-name", PLUGIN_NAME);
  headers.set("plugin-version", PLUGIN_VERSION);
  headers.set("x-ot-client-type", "opencode-codearts-auth");
  headers.set("x-ot-client-version", "0.1.0");
  if (opts?.maasType) headers.set("maas_type", opts.maasType);
  else headers.delete("maas_type");

  const signable = {};
  for (const name of SIGNED_HEADERS) {
    const value = headers.get(name);
    if (value !== null) signable[name] = value;
  }

  // 并发冲突是瞬时的：退避重试通常就能挤进去，不用把失败甩给用户
  const attempts = Math.max(1, Number(opts?.concurrencyRetries ?? 3));
  const delayMs = Math.max(0, Number(opts?.concurrencyRetryDelayMs ?? 800));
  const canReplay = typeof rawBody === "string" || rawBody instanceof Uint8Array || rawBody instanceof ArrayBuffer;

  // CodeArts 的配额是「账号级的同时活跃会话 ≤ 3」，所以插件这边自己把同一个账号的在飞请求掐到 1 个：
  // agent 的多轮/工具调用、magpie 的路由分类器都可能同时打请求，靠 magpie 的账号并发设置挡不住。
  const limit = Math.max(1, Number(opts?.maxInFlight ?? 1));
  const release = await acquireSlot(slotKeyOf(auth), limit, init?.signal);
  let released = false;
  const releaseOnce = () => {
    if (released) return;
    released = true;
    release();
  };

  let response;
  try {
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const signed = signRequest({ method, url, headers: signable, body }, auth.accessKey, auth.secretKey);
      for (const [key, value] of Object.entries(signed)) {
        if (key.toLowerCase() === "host") continue;
        headers.set(key, String(value));
      }
      response = await fetch(input, { ...init, headers });
      if (!canReplay || attempt === attempts) break;
      if (!(await isSessionLimit(response))) break;
      await sleep(delayMs * attempt + Math.floor(Math.random() * 200), init?.signal);
    }

    // 退避重试用尽仍然是并发上限：把原因和该怎么做写进错误信息
    if (await isSessionLimit(response)) {
      const annotated = await annotateSessionLimit(response, attempts);
      releaseOnce();
      return annotated;
    }

    // STS 还没到期就 401/403：多半问题不在登录本身，别让 magpie 因此把账号标记成需要重新登录。
    const expires = Number(auth.expires);
    if (
      (response.status === 401 || response.status === 403) &&
      Number.isFinite(expires) &&
      Date.now() < expires - 60_000
    ) {
      const patched = new Headers(response.headers);
      patched.set("X-Magpie-Sign-In", "kept");
      return holdSlotUntilBodyEnds(
        new Response(response.body, { status: response.status, statusText: response.statusText, headers: patched }),
        releaseOnce,
        init?.signal,
      );
    }

    // 流式响应的占用要一直持续到 magpie 读完，否则下一个请求立刻挤进来又变成一个会话
    return holdSlotUntilBodyEnds(response, releaseOnce, init?.signal);
  } catch (error) {
    releaseOnce();
    throw error;
  }
}

/**
 * 额度接口的错误分类：只有明确的鉴权失败才让 magpie 标记账号需要重新登录，
 * 其他错误（网络、5xx）转成中性文案，避免一次抖动就把账号标成失效。
 */
function describeQuotaError(label, error) {
  const message = String(error?.message ?? error);
  if (/401|403|unauthorized|forbidden|invalid_grant|APIG\.0301/i.test(message)) {
    return { text: "CodeArts 凭据已失效，需要重新登录该账号", signIn: "expired" };
  }
  const sanitized = message.replace(/\b(401|403|unauthorized|forbidden)\b/gi, "接口错误");
  return { text: `${label}接口暂时不可用：${sanitized}`.slice(0, 300) };
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
    const code = String(data?.error?.code ?? data?.error ?? data?.error_code ?? "");
    const message = data?.error?.message || data?.error_description || data?.error_msg || `HTTP ${res.status}`;
    // 只有明确的「刷新令牌失效」才让 magpie 把账号标记成需要重新登录；
    // 网络/5xx 之类交给 magpie 之后重试，避免一次抖动就要求用户重新登录。
    const expired =
      res.status === 400 ||
      res.status === 401 ||
      res.status === 403 ||
      /invalid_grant|expired|unauthorized/i.test(`${code} ${message}`);
    const error = new Error(`CodeArts token refresh failed: ${message}`);
    if (expired) error.signIn = "expired";
    throw error;
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

/**
 * 额度 / 积分：GET {snap}/snap-manager/v1/statistics/plugin
 * metrics[] 里的 package_credit_* 是「余额提醒」的真正来源
 * （客户端的 /snap-manager/v1/package/overview 在现网返回 404 APIG.0101）。
 */
async function fetchQuotaStats(auth) {
  const url = `${SNAP_ENGINE}/snap-manager/v1/statistics/plugin`;
  const res = await signedFetch(auth, { method: "GET", url });
  return res.data;
}

const QUOTA_WINDOW_LABELS = {
  usageTotalPackageCredit: "积分总额",
  usageBasicPackageCredit: "基础套餐积分",
  usageBonusPackageCredit: "赠送积分",
  usageOnDemandPackageCredit: "按需积分",
  usageTokenChatMessages: "对话 tokens",
  usageDataChatMessages: "对话次数",
};

function packageWindows(stats) {
  const metrics = Array.isArray(stats?.metrics) ? stats.metrics : [];
  const windows = [];
  for (const metric of metrics) {
    const key = metric?.name;
    if (!key || metric.show === false) continue;
    const used = num(metric.package_credit_used);
    const amount = num(metric.package_credit_amount);
    const remain = num(metric.package_credit_remain);
    const expiring = num(metric.package_credit_expiring_amount);
    const usedTokens = num(metric.usage_token_num);
    const tokenAmount = num(metric.package_token_amount);
    const isCredits = amount !== undefined && amount > 0;
    const isTokens = !isCredits && tokenAmount !== undefined && tokenAmount > 0;
    // 明显不成比例的 tokens 窗口（例如 package_token_amount 是 1 却用了 1300 万 token）
    // 说明这个字段不是额度，跳过它，别在界面上给出误导数字
    if (isTokens && usedTokens !== undefined && usedTokens > tokenAmount * 10) continue;
    // 全是 0 的窗口没有信息量（例如未开通的按需计费），不往界面上堆
    if (!isCredits && !isTokens && usedTokens !== -1) continue;
    const unlimited = usedTokens === -1 || tokenAmount === -1;
    const display = unlimited
      ? "不限量"
      : isCredits
        ? `已用 ${used ?? 0} / ${amount} 积分，剩 ${remain ?? Math.max(0, amount - (used ?? 0))}${expiring ? `（${expiring} 即将过期）` : ""}`
        : `已用 ${usedTokens ?? 0} / ${tokenAmount} tokens`;
    windows.push({
      name: QUOTA_WINDOW_LABELS[key] ?? key,
      used: isCredits
        ? used !== undefined
          ? (used * 100) / amount
          : undefined
        : isTokens && usedTokens !== undefined
          ? (usedTokens * 100) / tokenAmount
          : undefined,
      // amount = 已用，limit = 总量：magpie 的界面按这个顺序显示（反过来会看到「0 / 16500」）
      amount: isCredits ? used : usedTokens,
      limit: isCredits ? amount : tokenAmount,
      unit: isCredits ? "积分" : "tokens",
      display,
      ...(key === "usageTotalPackageCredit" ? { span: 30 * 24 * 3600 } : {}),
    });
  }
  return windows;
}

/** 剩余积分（auth.usage 的 balance）。 */
function creditsFromStats(stats) {
  const metrics = Array.isArray(stats?.metrics) ? stats.metrics : [];
  const total = metrics.find((metric) => metric?.name === "usageTotalPackageCredit");
  return {
    remain: num(total?.package_credit_remain),
    amount: num(total?.package_credit_amount),
    used: num(total?.package_credit_used),
  };
}

/**
 * 把 agent-center 的模型细节并进「账号可用的模型」列表。
 * 只补细节、不加新 id：agent-center 列的是平台上存在的模型，账号未必有权使用。
 */
function mergeModelDetails(available, detailed) {
  const byId = new Map(available.map((model) => [model.id, { ...model }]));
  for (const model of Array.isArray(detailed) ? detailed : []) {
    const existing = byId.get(model.id);
    if (!existing) continue;
    existing.context = existing.context ?? model.context;
    existing.output = existing.output ?? model.output;
    existing.image = existing.image ?? model.image;
    existing.reasoning = existing.reasoning ?? model.reasoning;
  }
  return [...byId.values()];
}

/** 账号可用的模型：statistics/plugin 的 model_metrics。 */
function modelsFromStats(stats) {
  const models = Array.isArray(stats?.model_metrics) ? stats.model_metrics : [];
  return models
    .filter((model) => model?.model_id && model.enable !== false)
    .map((model) => ({
      id: model.model_id,
      name: model.model_name || model.model_id,
      description: model.model_desc,
      quota: num(model.model_quota_num),
      luxury: Boolean(model.is_luxury),
    }));
}

/** 权益渠道余额：GET {benefit}/api/v1/user/tokens/balance（渠道未开通时返回 error_code 4000）。 */
async function fetchBalance(auth, channel) {
  const base = `${BENEFIT_API}/api/v1/user/tokens/balance`;
  const url = channel ? `${base}?channel=${encodeURIComponent(channel)}` : base;
  const res = await signedFetch(auth, { method: "GET", url });
  const data = res.data;
  if (data?.error_code && data.error_code !== "0000") {
    return {
      notEnabled: data.error_code === "4000",
      error: data.error_code === "4000"
        ? `权益渠道未开通（${data.error_msg ?? "invalid channel"}）`
        : `余额接口返回 error_code=${data.error_code}`,
    };
  }
  const result = data?.result ?? data;
  const tokens = firstOf(
    num(result?.available_tokens),
    num(result?.remain_tokens),
    num(result?.balance),
    num(result?.tokens),
    num(result?.total),
  );
  return { raw: result, tokens };
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

/** 权益渠道领取：POST {benefit}/api/v1/benefit/claim[?channel=…]（渠道开通时才有意义） */
async function claimBenefit(auth, channel) {
  const base = `${BENEFIT_API}/api/v1/benefit/claim`;
  const url = channel ? `${base}?channel=${encodeURIComponent(channel)}` : base;
  const res = await signedFetch(auth, { method: "POST", url, body: "{}" });
  const data = res.data;
  const code = data?.error_code;
  return {
    ok: code === "0000" || code === undefined || code === 0,
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
  return { ok, items: Array.isArray(data?.data?.items) ? data.data.items : [], raw: data };
}

/** 每日签到的活动：优先 USER_LOGIN 类型，其次标题里带「签到」，最后退到任意可领活动。 */
function pickCheckinCampaign(items) {
  const list = Array.isArray(items) ? items : [];
  const claimable = list.filter((item) => item?.claimable === true);
  return (
    claimable.find((item) => String(item?.type ?? "").toUpperCase() === "USER_LOGIN") ??
    claimable.find((item) => /签到|登录/.test(`${item?.title ?? ""}${item?.type ?? ""}`)) ??
    claimable[0]
  );
}

/** 领取福利：POST {policyCenter}/v1/ops/claim */
async function claimWelfare(auth, campaignId, idempotentKey = crypto.randomUUID()) {
  const url = `${SNAP_ENGINE}/v1/ops/claim`;
  const body = JSON.stringify({ campaignId, idempotentKey, channel: "DESKTOP" });
  const res = await signedFetch(auth, { method: "POST", url, body });
  const data = res.data;
  const payload = data?.data ?? data?.result;
  return {
    ok: data?.code === 0 || data?.code === 200 || payload !== undefined,
    message: data?.message,
    userBenefitId: payload?.userBenefitId ?? payload?.user_benefit_id ?? payload?.id,
    data: payload,
  };
}

/** 确认到账：POST {policyCenter}/v1/ops/confirm */
async function confirmWelfare(auth, userBenefitId) {
  const url = `${SNAP_ENGINE}/v1/ops/confirm`;
  const body = JSON.stringify({ userBenefitId });
  const res = await signedFetch(auth, { method: "POST", url, body });
  const data = res.data;
  return {
    ok: data?.code === 0 || data?.code === 200 || data?.data !== undefined,
    message: data?.message,
    data: data?.data,
  };
}

/** 没有可领活动时的结论：签到活动还在但不可领 = 今天已经签过了。 */
function noClaimableCheckin(items) {
  const list = Array.isArray(items) ? items : [];
  const loginCampaign = list.find((item) => String(item?.type ?? "").toUpperCase() === "USER_LOGIN");
  if (loginCampaign) {
    return {
      status: "already",
      message: loginCampaign.status ? `今日已签到（${loginCampaign.status}）` : "今日已签到",
      campaign: loginCampaign,
    };
  }
  return { status: "none", message: "当前没有可领取的签到活动", items: list };
}

/**
 * 每日签到一条龙：delivery 找可领的 USER_LOGIN 活动 → claim → confirm。
 * 这是 CodeArts 客户端「每日签到领 1000 积分」走的那条链路。
 */
async function runCheckin(auth, { claim = true } = {}) {
  const delivery = await fetchWelfareDelivery(auth);
  if (!delivery.ok) {
    return { status: "unavailable", message: "福利接口不可用（登录可能已失效）" };
  }
  const campaign = pickCheckinCampaign(delivery.items);
  if (!campaign) return noClaimableCheckin(delivery.items);
  if (!claim) {
    // 只读模式：不领取，但把「有可领的签到」如实说出来
    return {
      status: "available",
      message: `可以签到（${campaign.title ?? "每日签到"} +${campaign.benefitAmount ?? "?"}）`,
      campaign,
    };
  }
  const claimResult = await claimWelfare(auth, campaign.campaignId);
  if (!claimResult.ok) {
    return { status: "failed", message: claimResult.message ?? "领取失败", campaign, claim: claimResult };
  }
  let confirmed;
  if (claimResult.userBenefitId !== undefined && claimResult.userBenefitId !== null) {
    confirmed = await confirmWelfare(auth, claimResult.userBenefitId);
  }
  return { status: "claimed", campaign, claim: claimResult, confirmed };
}

/** 把福利活动列表转成给人看的几行。 */
function describeCampaigns(items) {
  const list = Array.isArray(items) ? items : [];
  if (list.length === 0) return "（福利中心没有返回活动）";
  return list
    .map((item) => {
      const state = item.claimable ? "可领取" : String(item.status ?? "未参与");
      return `· #${item.campaignId} ${item.title ?? item.type ?? ""} +${item.benefitAmount ?? "?"} ${item.benefitUnit ?? ""}（${state}）`;
    })
    .join("\n");
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

/**
 * 签到的每日门控：
 * - `autoCheckin` 打开时，今天没领过就直接领（额度刷新、工具调用都会走到这里）；
 * - 关掉时只读状态，不领取——但仍然会告诉调用方今天签没签。
 * 服务端自己会对当天重复领取返回「不可领」，这里的状态文件只是省一次请求的缓存。
 */
async function resolveCheckin(auth, options = {}, directory, { force = false } = {}) {
  const state = directory ? readCheckinState(directory) : {};
  if (!force && options.autoCheckin !== true && directory && state.lastCheckin === today()) {
    // 今天已经领过了，直接用缓存，省一次网络往返
    if (state.lastResult === "claimed") {
      return { status: "claimed", message: state.lastMessage, campaign: { benefitAmount: state.lastCredit } };
    }
    if (state.lastResult === "already") return { status: "already", message: state.lastMessage };
  }
  if (!force && options.autoCheckin !== true && !directory) {
    // 没有状态目录时不能缓存，仍然只读一次状态
  }
  const allowClaim = force || options.autoCheckin === true;
  const result = await runCheckin(auth, { claim: allowClaim });
  if (directory && allowClaim) {
    const next = { ...state, lastCheckin: today(), lastResult: result.status, lastMessage: result.message };
    if (result.campaign?.benefitAmount) next.lastCredit = result.campaign.benefitAmount;
    writeCheckinState(directory, next);
  }
  return result;
}

// ─── 插件 ─────────────────────────────────────────────────────────────────────
export const CodeArtsAuthPlugin = async ({ directory }, pluginOptions) => {
  // magpie 会把插件函数第二个参数（plugins.json 里这一项的 options）传进来；
  // 拿不到时回落到配置文件，最后用默认值。
  const defaults = {
    channel: "benefit",
    maasType: "",
    autoCheckin: true,
    account: "",
    concurrencyRetries: 3,
    concurrencyRetryDelayMs: 800,
    maxInFlight: 1,
  };
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
    // 供应商声明：magpie 未登录时也能列出这些模型（都是账号侧确认可用的 id）
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
              headers.delete("authorization");
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
            return forwardSigned(auth, opts, input, init);
          },
        };
      },

      /** 余额提醒：magpie 的账号额度窗口 / magpie quota / GET /v1/magpie/quotas。 */
      async usage(getAuth) {
        const auth = await accountOf(getAuth);
        if (!auth?.accessKey) return { windows: [], error: "CodeArts 账号尚未授权" };
        const opts = await getOptions();
        const result = { windows: [] };
        let failed = false;

        try {
          const stats = await fetchQuotaStats(auth);
          result.windows.push(...packageWindows(stats));
          const credits = creditsFromStats(stats);
          if (credits.remain !== undefined) {
            result.balance = `${credits.remain} 积分（共 ${credits.amount ?? "?"}，已用 ${credits.used ?? 0}）`;
          }
          const models = modelsFromStats(stats);
          if (models.length > 0) result.plan = result.plan ?? `CodeArts · ${models.length} 个可用模型`;
        } catch (error) {
          failed = true;
          const described = describeQuotaError("额度", error);
          if (!result.error) result.error = described.text;
          if (described.signIn) result.signIn = described.signIn;
        }

        // 权益渠道余额：渠道没开通时（error_code 4000）不当成错误，它只是没这个渠道
        try {
          const balance = await fetchBalance(auth, opts.channel);
          if (balance.error && !balance.notEnabled) {
            if (!result.error) result.error = balance.error;
          } else if (balance.tokens !== undefined) {
            result.balance = `${balance.tokens} tokens（${opts.channel ?? "benefit"} 渠道）`;
          }
        } catch (error) {
          const described = describeQuotaError("余额", error);
          if (described.signIn) {
            failed = true;
            if (!result.error) result.error = described.text;
            result.signIn = described.signIn;
          }
        }

        // 签到：默认每天自动领一次；关掉 autoCheckin 后仍会显示今天的签到状态
        try {
          const checkin = await resolveCheckin(auth, opts, directory);
          if (checkin.status === "claimed") {
            result.windows.push({
              name: "今日签到",
              display: `已领取 +${checkin.campaign?.benefitAmount ?? "?"} 积分`,
            });
          } else if (checkin.status === "already") {
            result.windows.push({ name: "今日签到", display: "今日已签到" });
          }
        } catch (error) {
          result.windows.push({ name: "今日签到", display: `签到未完成：${String(error?.message ?? error)}` });
        }

        return result;
      },
    },

    /** 账号自己的模型列表：权益渠道 + 内置 inferhub 模型。 */
    provider: {
      id: PROVIDER,
      async models(provider, { auth } = {}) {
        if (auth?.type !== "oauth" || !auth?.accessKey) return provider.models;
        let found = [];
        // 账号侧的权威列表（带启用状态）：statistics/plugin 的 model_metrics
        try {
          found = modelsFromStats(await fetchQuotaStats(auth));
        } catch {
          found = [];
        }
        // 用 agent-center 的细节补上下文长度与多模态。
        // 注意：agent-center 返回的是「平台有的模型」，不是「这个账号能用的」，
        // 所以只允许补细节，绝不允许把里面多出来的 id 加进列表 ——
        // 选了账号没有的模型，服务端会回 404 InferHub.002002009 "The model is not registered"。
        try {
          const detailed = await fetchBuiltinModels(auth);
          found = mergeModelDetails(found, detailed);
        } catch {
          /* 细节拿不到就用账号列表 */
        }
        try {
          if (await fetchGatewayEnabled(auth, "benefit")) {
            found = [...found, ...(await fetchChannelModels(auth, "benefit"))];
          }
          if (await fetchGatewayEnabled(auth, "education")) {
            found = [...found, ...(await fetchChannelModels(auth, "education"))];
          }
        } catch {
          /* 权益渠道不可用时只用账号列表 */
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
        description: "CodeArts 每日签到：领取「每日签到」活动积分（走 delivery → claim → confirm），并回读积分余额。",
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
          // 工具是用户显式要求，所以就算没开 autoCheckin 也直接领
          const result = await resolveCheckin(auth, opts, directory, { force: true });

          const lines = [];
          if (result.status === "claimed") {
            lines.push(
              `✅ 签到成功：${result.campaign.title ?? "每日签到"} +${result.campaign.benefitAmount ?? "?"} ${result.campaign.benefitUnit ?? ""}`.trim(),
            );
            if (result.confirmed && result.confirmed.ok === false && result.confirmed.message) {
              lines.push(`（到账确认接口返回：${result.confirmed.message}）`);
            }
          } else if (result.status === "already") {
            lines.push(`今日已签到，明天再来（${result.message}）`);
          } else if (result.status === "available") {
            lines.push(
              `⚠️ 有可领的签到但没领成：${result.message}。可以先确认 magpie 里的账号登录还有效，再重试。`,
            );
          } else if (result.status === "none") {
            lines.push(`没有可领取的签到活动：${describeCampaigns(result.items ?? [])}`);
          } else {
            lines.push(`⚠️ 签到未完成（${result.status}）：${result.message ?? "未知原因"}`);
            if (result.status === "unavailable") {
              lines.push("如果是登录失效，请在 magpie 里重新登录该账号。");
            }
          }
          const stats = await fetchQuotaStats(auth).catch(() => undefined);
          const credits = creditsFromStats(stats);
          if (credits.remain !== undefined) {
            lines.push(`当前积分：${credits.remain} / ${credits.amount ?? "?"}（已用 ${credits.used ?? 0}）`);
          }
          return lines.join("\n");
        },
      },
      balance: {
        description: "查询 CodeArts 账号积分余额、额度窗口与可用模型。",
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
            const stats = await fetchQuotaStats(auth);
            const credits = creditsFromStats(stats);
            if (credits.remain !== undefined) {
              lines.push(`积分：${credits.remain} / ${credits.amount ?? "?"}（已用 ${credits.used ?? 0}）`);
            }
            for (const window of packageWindows(stats)) {
              lines.push(`· ${window.name}：${window.display ?? `${Math.round(window.used ?? 0)}%`}`);
            }
            const models = modelsFromStats(stats);
            if (models.length > 0) lines.push(`可用模型：${models.map((model) => model.name).join(", ")}`);
          } catch (error) {
            lines.push(`额度接口读取失败：${String(error?.message ?? error)}`);
          }
          try {
            const balance = await fetchBalance(auth, channel);
            if (balance.tokens !== undefined) lines.push(`渠道余额：${balance.tokens} tokens`);
            else if (balance.notEnabled) lines.push(`渠道余额：${opts.channel ?? "benefit"} 渠道未开通`);
            else if (balance.error) lines.push(`渠道余额：${balance.error}`);
          } catch (error) {
            lines.push(`渠道余额读取失败：${String(error?.message ?? error)}`);
          }
          return lines.join("\n");
        },
      },
      welfare: {
        description: "查看 CodeArts 福利中心的全部活动（签到/邀请/新人）与领取状态，不自动领取。",
        args: { type: "object", properties: {}, additionalProperties: false },
        async execute(_args, ctx) {
          const auth = await resolveAccount();
          if (!auth?.accessKey) return "未登录 CodeArts，请先在 magpie 里登录该供应商。";
          const delivery = await fetchWelfareDelivery(auth);
          if (!delivery.ok) return `福利接口返回异常：${JSON.stringify(delivery.raw).slice(0, 400)}`;
          return describeCampaigns(delivery.items);
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
  SIGNED_HEADERS,
  forwardSigned,
  describeQuotaError,
  generatePkcePair,
  generateDpopProof,
  generateDpopKeyPair,
  buildAuthorizeUrl,
  sessionFromTokenResponse,
  packageWindows,
  creditsFromStats,
  modelsFromStats,
  mergeModelDetails,
  fetchQuotaStats,
  pickCheckinCampaign,
  noClaimableCheckin,
  describeCampaigns,
  runCheckin,
  resolveCheckin,
  DEFAULT_MODELS,
};
