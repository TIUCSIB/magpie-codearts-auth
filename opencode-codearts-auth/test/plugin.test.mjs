import { describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import { _internal } from "../index.mjs";

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
  test("把 package overview 的 metrics 变成 magpie 窗口", () => {
    const windows = packageWindows({
      metrics: [
        {
          name: "usageToken",
          show: true,
          usage_token_num: 250,
          package_token_amount: 1000,
        },
        {
          name: "credit",
          show: true,
          package_credit_used: 30,
          package_credit_amount: 100,
          package_credit_remain: 70,
          package_credit_expiring_amount: 10,
        },
      ],
    });
    expect(windows).toHaveLength(2);
    expect(windows[0].used).toBeCloseTo(25);
    expect(windows[1].unit).toBe("credits");
    expect(windows[1].display).toContain("30 / 100 credits");
  });

  test("不限量时给出可读文案", () => {
    const [window] = packageWindows({
      metrics: [{ name: "usageToken", usage_token_num: -1, package_token_amount: -1 }],
    });
    expect(window.display).toBe("不限量");
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
