import { describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import { CodeArtsAuthPlugin, _internal } from "../index.mjs";

const {
  signRequest,
  canonicalUriOf,
  sdkDate,
  sha256Hex,
  generatePkcePair,
  generateDpopKeyPair,
  generateDpopProof,
  buildAuthorizeUrl,
  sessionFromTokenResponse,
  packageWindows,
  INFERHUB_BASE,
  DEFAULT_MODELS,
} = _internal;

describe("华为云签名", () => {
  test("canonicalUri 会编码路径段并补齐结尾斜杠", () => {
    expect(canonicalUriOf("/api/v1/user/tokens/balance")).toBe("/api/v1/user/tokens/balance/");
    expect(canonicalUriOf("/api/v2/chat/completions")).toBe("/api/v2/chat/completions/");
  });

  test("sdkDate 是 UTC 的 YYYYMMDDTHHMMSSZ", () => {
    expect(sdkDate(new Date(Date.UTC(2026, 9, 21, 1, 2, 3)))).toBe("20261021T010203Z");
  });

  test("签名头包含 Authorization / X-Sdk-Date / host，且 SignedHeaders 按字典序", () => {
    const headers = signRequest(
      {
        method: "GET",
        url: "https://example.com/api/v1/user/tokens/balance?channel=benefit",
        headers: { "X-Security-Token": "sts", "Content-Type": "application/json" },
      },
      "AK",
      "SK",
      new Date(Date.UTC(2026, 9, 21, 1, 2, 3)),
    );
    expect(headers.Authorization).toStartWith("SDK-HMAC-SHA256 Access=AK, SignedHeaders=");
    expect(headers["X-Sdk-Date"]).toBe("20261021T010203Z");
    expect(headers.host).toBe("example.com");
    const signed = headers.Authorization.match(/SignedHeaders=([^,]+)/)[1].split(";");
    expect(signed).toEqual([...signed].sort());
    expect(signed).toContain("x-security-token");
    expect(signed).toContain("host");
  });

  test("签名对 body 敏感、对时间敏感，同一输入可复现", () => {
    const at = new Date(Date.UTC(2026, 9, 21, 1, 2, 3));
    const base = {
      method: "POST",
      url: "https://example.com/api/v1/benefit/claim",
      headers: { "X-Security-Token": "sts", "Content-Type": "application/json" },
    };
    const a = signRequest({ ...base, body: "{}" }, "AK", "SK", at);
    const b = signRequest({ ...base, body: "{}" }, "AK", "SK", at);
    const c = signRequest({ ...base, body: '{"x":1}' }, "AK", "SK", at);
    const d = signRequest({ ...base, body: "{}" }, "AK", "SK", new Date(Date.UTC(2026, 9, 21, 1, 2, 4)));
    expect(a.Authorization).toBe(b.Authorization);
    expect(c.Authorization).not.toBe(a.Authorization);
    expect(d.Authorization).not.toBe(a.Authorization);
  });

  test("body 哈希是 sha256 十六进制", () => {
    expect(sha256Hex("{}")).toBe(crypto.createHash("sha256").update("{}").digest("hex"));
  });
});

describe("PKCE 与 DPoP", () => {
  test("code_challenge = base64url(sha256(verifier))，无 padding", () => {
    const { codeVerifier, codeChallenge } = generatePkcePair();
    const expected = crypto
      .createHash("sha256")
      .update(codeVerifier)
      .digest()
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(codeChallenge).toBe(expected);
    expect(codeVerifier).toHaveLength(128);
    expect(codeChallenge).not.toContain("=");
  });

  test("DPoP proof 是三段 JWT、typ=dpop+jwt，并且能被公钥验签", async () => {
    const keyPair = await generateDpopKeyPair();
    const url = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens";
    const proof = await generateDpopProof(keyPair, "POST", url);
    const [headerPart, payloadPart, signaturePart] = proof.split(".");
    expect(signaturePart).toBeTruthy();

    const header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
    expect(header.typ).toBe("dpop+jwt");
    expect(header.alg).toBe("ES256");
    expect(header.jwk.crv).toBe("P-256");
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe(url);
    expect(typeof payload.jti).toBe("string");

    const publicKey = await crypto.subtle.importKey(
      "jwk",
      header.jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      Buffer.from(signaturePart, "base64url"),
      new TextEncoder().encode(`${headerPart}.${payloadPart}`),
    );
    expect(ok).toBe(true);
  });

  test("DPoP proof 每次 jti 不同", async () => {
    const keyPair = await generateDpopKeyPair();
    const url = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens";
    const one = await generateDpopProof(keyPair, "POST", url);
    const two = await generateDpopProof(keyPair, "POST", url);
    expect(one).not.toBe(two);
  });
});

describe("登录 URL 与账号字段", () => {
  test("授权 URL 带上客户端要求的所有参数", () => {
    const url = new URL(
      buildAuthorizeUrl({ port: 18888, codeChallenge: "CH", ticketId: "TICKET" }),
    );
    expect(url.origin + url.pathname).toBe("https://codearts.huaweicloud.com/portal/authorize");
    const params = url.searchParams;
    expect(params.get("client_id")).toBe("codearts");
    expect(params.get("uri_scheme")).toBe("codearts");
    expect(params.get("port")).toBe("18888");
    expect(params.get("code_challenge")).toBe("CH");
    expect(params.get("code_challenge_method")).toBe("SHA-256");
    expect(params.get("ticket_id")).toBe("TICKET");
    expect(params.get("plugin-name")).toBe("snap_AIIDE");
    expect(params.get("plugin-version")).toBe("5.1.0");
  });

  test("token 响应折成 magpie 账号字段", () => {
    const session = sessionFromTokenResponse(
      {
        credentials: {
          access_key_id: "AKID",
          secret_access_key: "SK",
          security_token: "ST",
          expiration: "2026-10-21T03:00:00.000Z",
        },
        refresh_token: "RT",
      },
      { codeVerifier: "cv" },
    );
    expect(session.access).toBe("ST");
    expect(session.refresh).toBe("RT");
    expect(session.accessKey).toBe("AKID");
    expect(session.secretKey).toBe("SK");
    expect(session.codeVerifier).toBe("cv");
    expect(session.expires).toBe(Date.parse("2026-10-21T03:00:00.000Z"));
  });

  test("没有 credentials 时按登录失效抛出", () => {
    let thrown;
    try {
      sessionFromTokenResponse({ refresh_token: "RT" });
    } catch (error) {
      thrown = error;
    }
    expect(thrown?.signIn).toBe("expired");
  });
});

describe("额度窗口解析", () => {
  test("把 statistics/plugin 的 metrics 变成 magpie 窗口", () => {
    const windows = packageWindows({
      metrics: [
        {
          name: "usageTokenChatMessages",
          show: true,
          usage_token_num: 250,
          package_token_amount: 1000,
        },
        {
          name: "usageTotalPackageCredit",
          show: true,
          package_credit_used: 974.89,
          package_credit_amount: 15500,
          package_credit_remain: 14525.11,
          package_credit_expiring_amount: 0,
        },
      ],
    });
    expect(windows).toHaveLength(2);
    expect(windows[0].name).toBe("对话 tokens");
    expect(windows[0].used).toBeCloseTo(25);
    expect(windows[1].name).toBe("积分总额");
    expect(windows[1].unit).toBe("积分");
    expect(windows[1].used).toBeCloseTo(6.2897, 3);
    // amount = 已用、limit = 总量：界面按「已用 / 总量」显示
    expect(windows[1].amount).toBeCloseTo(974.89);
    expect(windows[1].limit).toBe(15500);
    expect(windows[1].display).toContain("974.89 / 15500 积分");
    expect(windows[1].display).toContain("14525.11");
  });

  test("不限量时给出可读文案", () => {
    const [window] = packageWindows({
      metrics: [{ name: "usageTokenChatMessages", usage_token_num: -1, package_token_amount: -1 }],
    });
    expect(window.display).toBe("不限量");
  });

  test("全 0 的窗口（未开通按需计费）不进界面", () => {
    const windows = packageWindows({
      metrics: [
        { name: "usageOnDemandPackageCredit", show: true, package_credit_used: 0, package_credit_amount: 0 },
        { name: "usageBasicPackageCredit", show: true, package_credit_used: 0, package_credit_amount: 500 },
      ],
    });
    expect(windows).toHaveLength(1);
    expect(windows[0].name).toBe("基础套餐积分");
  });

  test("不成比例的 tokens 窗口不显示（package_token_amount 不是额度）", () => {
    const windows = packageWindows({
      metrics: [{ name: "usageTokenChatMessages", show: true, usage_token_num: 13645620, package_token_amount: 1 }],
    });
    expect(windows).toHaveLength(0);
  });

  test("剩余积分取总额度窗口", () => {
    const credits = _internal.creditsFromStats({
      metrics: [
        { name: "usageTotalPackageCredit", package_credit_amount: 15500, package_credit_used: 974.89, package_credit_remain: 14525.11 },
      ],
    });
    expect(credits.remain).toBe(14525.11);
    expect(credits.used).toBe(974.89);
  });
});

describe("模型列表与签到活动", () => {
  test("model_metrics 只保留启用的模型", () => {
    const models = _internal.modelsFromStats({
      model_metrics: [
        { model_id: "GLM-5.2", model_name: "GLM-5.2", model_desc: "旗舰", enable: true },
        { model_id: "old-model", model_name: "Old", enable: false },
      ],
    });
    expect(models).toHaveLength(1);
    expect(models[0]).toEqual({ id: "GLM-5.2", name: "GLM-5.2", description: "旗舰", quota: undefined, luxury: false });
  });

  test("不会把账号没有的模型加进列表（glm-5.3-flash 会 404 not registered）", () => {
    const merged = _internal.mergeModelDetails(
      [{ id: "glm-5.3", name: "GLM-5.3" }],
      [
        { id: "glm-5.3", context: 200000, output: 64000, image: false },
        { id: "glm-5.3-flash", context: 128000 },
      ],
    );
    expect(merged.map((model) => model.id)).toEqual(["glm-5.3"]);
    expect(merged[0].context).toBe(200000);
    expect(merged[0].output).toBe(64000);
  });

  test("签到优先选 USER_LOGIN 且只挑可领取的活动", () => {
    const items = [
      { campaignId: 4, type: "NEW_USER_REGISTER", claimable: false, title: "新用户注册送 4000 积分" },
      { campaignId: 3, type: "INVITE_USER", claimable: true, title: "推荐码上有礼" },
      { campaignId: 1, type: "USER_LOGIN", claimable: true, title: "每日签到领1000积分" },
    ];
    expect(_internal.pickCheckinCampaign(items).campaignId).toBe(1);
    expect(_internal.pickCheckinCampaign([items[1]]).campaignId).toBe(3);
    expect(_internal.pickCheckinCampaign([items[0]])).toBeUndefined();
    expect(_internal.pickCheckinCampaign([])).toBeUndefined();
  });

  test("签到活动还在但不可领 = 今天已签到", () => {
    const result = _internal.noClaimableCheckin([
      { campaignId: 1, type: "USER_LOGIN", status: "CLAIMED", claimable: false, title: "每日签到领1000积分" },
    ]);
    expect(result.status).toBe("already");
    expect(result.message).toContain("CLAIMED");
    expect(_internal.noClaimableCheckin([]).status).toBe("none");
    const none = _internal.noClaimableCheckin([{ campaignId: 3, type: "INVITE_USER", claimable: false }]);
    expect(none.status).toBe("none");
  });

  test("活动列表能转成可读文案", () => {
    const text = _internal.describeCampaigns([
      { campaignId: 1, type: "USER_LOGIN", title: "每日签到领1000积分", benefitAmount: 1000, benefitUnit: "CREDIT", claimable: true },
      { campaignId: 4, type: "NEW_USER_REGISTER", title: "新用户注册送 4000 积分", benefitAmount: 4000, benefitUnit: "CREDIT", status: "CONFIRMED" },
    ]);
    expect(text).toContain("#1 每日签到领1000积分 +1000 CREDIT（可领取）");
    expect(text).toContain("#4 新用户注册送 4000 积分 +4000 CREDIT（CONFIRMED）");
  });
});

describe("供应商常量", () => {
  test("推理端点指向 inferhub 的 OpenAI 兼容路径", () => {
    expect(INFERHUB_BASE).toBe("https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/");
    expect(new URL("chat/completions", INFERHUB_BASE).href).toBe(
      "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions",
    );
  });

  test("默认模型表非空且带 limit", () => {
    const models = Object.values(DEFAULT_MODELS);
    expect(models.length).toBeGreaterThan(0);
    for (const model of models) {
      expect(model.context).toBeGreaterThan(0);
      expect(model.output).toBeGreaterThan(0);
    }
  });
});

describe("请求转发（真实故障的回归测试）", () => {
  // 现场故障：把 AI SDK / magpie 传来的所有头都纳入签名，包括它自己会覆盖掉的
  // authorization，服务端验签失败 → 401 verify ak sk signature fail → magpie 把账号
  // 标记成「需要重新登录」。
  // 每个用例用独立的 accountId：并发闸门按账号分组，共用同一个 id 会让没读完响应的用例
  // 把后面的用例全排进队列。
  const account = () => ({
    type: "oauth",
    accessKey: "AK",
    secretKey: "SK",
    securityToken: "ST",
    accountId: crypto.randomUUID(),
    expires: Date.now() + 3_600_000,
  });

  const withStubFetch = async (run) => {
    const original = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (input, init) => {
      calls.push({ input, headers: new Headers(init?.headers), body: init?.body });
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    };
    try {
      return await run(calls);
    } finally {
      globalThis.fetch = original;
    }
  };

  const loaderFetch = async (auth = account(), options = {}) => {
    const hooks = await CodeArtsAuthPlugin({ directory: process.cwd() }, options);
    const config = await hooks.auth.loader(async () => auth);
    return config.fetch;
  };

  test("baseURL 与 model 请求都指向 inferhub", async () => {
    const hooks = await CodeArtsAuthPlugin({ directory: process.cwd() }, {});
    const config = await hooks.auth.loader(async () => account());
    expect(config.baseURL).toBe(INFERHUB_BASE);
  });

  test("只把白名单头纳入签名，authorization 由签名接管", async () => {
    const forward = await loaderFetch();
    await withStubFetch(async (calls) => {
      await forward("https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer ",
          accept: "*/*",
          "user-agent": "Bun/1.4.3",
          "accept-encoding": "gzip, deflate",
        },
        body: '{"model":"GLM-5.1","messages":[]}',
      });
      expect(calls).toHaveLength(1);
      const { headers } = calls[0];
      const authorization = headers.get("authorization");
      expect(authorization).toStartWith("SDK-HMAC-SHA256 Access=AK, SignedHeaders=");
      const listed = authorization.match(/SignedHeaders=([^,]+)/)[1].split(";");
      expect(listed).not.toContain("authorization");
      expect(listed).not.toContain("accept");
      expect(listed).not.toContain("accept-encoding");
      expect(listed).not.toContain("user-agent");
      expect(listed).toContain("content-type");
      expect(listed).toContain("x-security-token");
      // 签名里列出的每个头都必须真的随请求发出，否则服务端同样验签失败。
      // host 例外：华为云签名规范要求它参与签名，但它是传输层按 URL 设置的，不出现在 fetch 的 headers 里。
      for (const name of listed) {
        if (name === "host") continue;
        expect(headers.has(name)).toBe(true);
      }
      expect(listed).toContain("host");
      expect(headers.get("host")).toBe(null);
      expect(headers.get("x-security-token")).toBe("ST");
      expect(headers.get("x-sdk-date")).toMatch(/^\d{8}T\d{6}Z$/);
    });
  });

  test("maas_type 只在显式配置时才发送（benefit 渠道不存在时会被服务端拒绝）", async () => {
    const plain = await loaderFetch();
    await withStubFetch(async (calls) => {
      await plain("https://example.test/api/v2/chat/completions", { method: "POST", body: "{}" });
      expect(calls[0].headers.has("maas_type")).toBe(false);
    });

    const benefited = await loaderFetch(account(), { maasType: "benefit" });
    await withStubFetch(async (calls) => {
      await benefited("https://example.test/api/v2/chat/completions", { method: "POST", body: "{}" });
      expect(calls[0].headers.get("maas_type")).toBe("benefit");
      const listed = calls[0].headers.get("authorization").match(/SignedHeaders=([^,]+)/)[1].split(";");
      expect(listed).toContain("maas_type");
    });
  });

  test("并发会话上限（TM.00001041）会退避重试而不是直接失败", async () => {
    const forward = await loaderFetch(account(), { concurrencyRetries: 3, concurrencyRetryDelayMs: 1 });
    const original = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      if (calls < 3) {
        return new Response(
          JSON.stringify({
            error_code: "TM.00001041",
            error_msg: "并发会话数已达上限(3个)，请关闭部分会话后重试。",
          }),
          { status: 400, headers: { "content-type": "application/json" } },
        );
      }
      return new Response('{"object":"chat.completion"}', { status: 200, headers: { "content-type": "application/json" } });
    };
    try {
      const res = await forward("https://example.test/api/v2/chat/completions", {
        method: "POST",
        body: '{"model":"GLM-5.1"}',
      });
      expect(calls).toBe(3);
      expect(res.status).toBe(200);
      expect(await res.text()).toContain("chat.completion");
    } finally {
      globalThis.fetch = original;
    }
  });

  test("重试用尽后给出可操作的并发上限说明", async () => {
    const forward = await loaderFetch(account(), { concurrencyRetries: 2, concurrencyRetryDelayMs: 1 });
    const original = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return new Response(
        JSON.stringify({ error_code: "TM.00001041", error_msg: "并发会话数已达上限(3个)，请关闭部分会话后重试。" }),
        { status: 400, headers: { "content-type": "application/json" } },
      );
    };
    try {
      const res = await forward("https://example.test/api/v2/chat/completions", { method: "POST", body: "{}" });
      expect(calls).toBe(2);
      expect(res.status).toBe(400);
      const body = await res.text();
      expect(body).toContain("TM.00001041");
      expect(body).toContain("重试 2 次");
      expect(body).toContain("并发");
    } finally {
      globalThis.fetch = original;
    }
  });

  test("同一账号的在飞请求被掐到 maxInFlight（默认 1）个", async () => {
    const forward = await loaderFetch(account(), { maxInFlight: 1, concurrencyRetries: 1 });
    const original = globalThis.fetch;
    let active = 0;
    let peak = 0;
    globalThis.fetch = async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 15));
      active -= 1;
      return new Response('{"ok":true}', { status: 200, headers: { "content-type": "application/json" } });
    };
    try {
      // 每个任务自己读完响应再结束：占用要等 body 读完才归还，不能在 Promise.all 里等齐响应
      const texts = await Promise.all(
        [0, 1, 2].map(async () => {
          const response = await forward("https://example.test/api/v2/chat/completions", {
            method: "POST",
            body: '{"model":"GLM-5.1"}',
          });
          return response.text();
        }),
      );
      expect(peak).toBe(1);
      expect(texts).toHaveLength(3);
      const after = await forward("https://example.test/api/v2/chat/completions", { method: "POST", body: "{}" });
      expect(after.status).toBe(200);
      await after.text();
    } finally {
      globalThis.fetch = original;
    }
  });

  test("STS 未过期时 401 会带上 X-Magpie-Sign-In: kept", async () => {
    const forward = await loaderFetch();
    const original = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response('{"error_code":"APIG.0301"}', { status: 401, headers: { "content-type": "application/json" } });
    try {
      const res = await forward("https://example.test/api/v2/chat/completions", { method: "POST", body: "{}" });
      expect(res.status).toBe(401);
      expect(res.headers.get("X-Magpie-Sign-In")).toBe("kept");
      expect(await res.text()).toContain("APIG.0301");
    } finally {
      globalThis.fetch = original;
    }
  });

  test("STS 已过期时的 401 保持原样，交给 magpie 标记重新登录", async () => {
    const forward = await loaderFetch({ ...account(), expires: Date.now() - 60_000 });
    const original = globalThis.fetch;
    globalThis.fetch = async () => new Response("{}", { status: 401 });
    try {
      const res = await forward("https://example.test/api/v2/chat/completions", { method: "POST", body: "{}" });
      expect(res.headers.get("X-Magpie-Sign-In")).toBe(null);
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe("额度错误分类", () => {
  test("鉴权失败才要求重新登录", () => {
    const described = _internal.describeQuotaError("余额", new Error("HTTP 401 Unauthorized"));
    expect(described.signIn).toBe("expired");
    expect(described.text).toContain("重新登录");
  });

  test("临时故障不使用会触发标记的措辞", () => {
    const described = _internal.describeQuotaError("套餐概览", new Error("HTTP 503 Service Unavailable"));
    expect(described.signIn).toBeUndefined();
    expect(described.text).not.toContain("登录");
    expect(described.text).toContain("暂时不可用");
  });
});
