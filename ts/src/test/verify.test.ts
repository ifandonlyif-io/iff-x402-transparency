import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DEFAULT_BASE_URL,
  VerifyRequestError,
  verify,
  verifyAccepts,
  type FetchLike,
  type VerifyInclusion,
  type VerifyResult,
} from "../verify.js";

function baseVerifyResult(): VerifyResult {
  return {
    url: "https://example.com/paid",
    verdict: "consistent",
    received: { set_fingerprint: "a".repeat(64), option_fingerprints: ["a".repeat(64)] },
    history: [],
    unmatched_received_options: [],
    ownership: { status: "verified" },
    inclusion: null,
    disclaimer: "Consistency with independent observation only. Not a safety, delivery, or payment guarantee.",
  };
}

test("verify posts to {baseUrl}/api/v3/verify with the url and payment_required fields", async () => {
  let capturedUrl: string | undefined;
  let capturedBody: unknown;
  const fetchImpl: FetchLike = (async (input: RequestInfo | URL, init?: RequestInit) => {
    capturedUrl = String(input);
    capturedBody = init?.body ? JSON.parse(init.body as string) : undefined;
    return new Response(JSON.stringify(baseVerifyResult()), { status: 200, headers: { "content-type": "application/json" } });
  }) as FetchLike;

  const paymentRequired = { x402Version: 2, accepts: [] };
  const result = await verify("https://example.com/paid", paymentRequired, { baseUrl: "https://staging.example", fetch: fetchImpl });

  assert.equal(capturedUrl, "https://staging.example/api/v3/verify");
  assert.deepEqual(capturedBody, { url: "https://example.com/paid", payment_required: paymentRequired });
  assert.equal(result.verdict, "consistent");
});

test("verify strips a trailing slash from baseUrl", async () => {
  let capturedUrl: string | undefined;
  const fetchImpl: FetchLike = (async (input: RequestInfo | URL) => {
    capturedUrl = String(input);
    return new Response(JSON.stringify(baseVerifyResult()), { status: 200 });
  }) as FetchLike;
  await verify("https://example.com/paid", { x402Version: 2, accepts: [] }, { baseUrl: "https://staging.example/", fetch: fetchImpl });
  assert.equal(capturedUrl, "https://staging.example/api/v3/verify");
});

test("verifyAccepts posts a bare accepts array", async () => {
  let capturedBody: unknown;
  const fetchImpl: FetchLike = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    capturedBody = init?.body ? JSON.parse(init.body as string) : undefined;
    return new Response(JSON.stringify(baseVerifyResult()), { status: 200 });
  }) as FetchLike;
  await verifyAccepts("https://example.com/paid", [{ scheme: "exact" }], { fetch: fetchImpl });
  assert.deepEqual(capturedBody, { url: "https://example.com/paid", accepts: [{ scheme: "exact" }] });
});

test("verify throws VerifyRequestError with status and parsed body on a non-2xx response", async () => {
  const fetchImpl: FetchLike = (async () =>
    new Response(JSON.stringify({ error: true, message: "invalid", check_code: "invalid_payment_option" }), {
      status: 422,
      headers: { "content-type": "application/json" },
    })) as FetchLike;

  await assert.rejects(
    () => verify("https://example.com/paid", { x402Version: 2, accepts: [] }, { fetch: fetchImpl }),
    (err: unknown) => {
      assert.ok(err instanceof VerifyRequestError);
      assert.equal(err.status, 422);
      assert.deepEqual(err.body, { error: true, message: "invalid", check_code: "invalid_payment_option" });
      return true;
    },
  );
});

test("DEFAULT_BASE_URL is used when no baseUrl is given", async () => {
  let capturedUrl: string | undefined;
  const fetchImpl: FetchLike = (async (input: RequestInfo | URL) => {
    capturedUrl = String(input);
    return new Response(JSON.stringify(baseVerifyResult()), { status: 200 });
  }) as FetchLike;
  await verify("https://example.com/paid", { x402Version: 2, accepts: [] }, { fetch: fetchImpl });
  assert.equal(capturedUrl, `${DEFAULT_BASE_URL}/api/v3/verify`);
});

test("verify exposes a populated Phase 3 inclusion proof with typed STH fields", async () => {
  const response = baseVerifyResult();
  response.inclusion = {
    observation_id: "11111111-1111-4111-8111-111111111111",
    observed_at: "2026-08-29T11:59:58Z",
    leaf_hash: "d".repeat(64),
    tree_size: 8,
    log_index: 3,
    audit_path: ["b".repeat(64)],
    sth: {
      log_id: "iff-log",
      tree_size: 8,
      timestamp: "2026-08-29T12:00:00Z",
      root_hash: "c".repeat(64),
      signature: "signature",
      public_key: "public-key",
    },
  };
  const fetchImpl: FetchLike = (async () => new Response(JSON.stringify(response), { status: 200 })) as FetchLike;

  const result = await verify("https://example.com/paid", { x402Version: 2, accepts: [] }, { fetch: fetchImpl });

  assert.equal(result.inclusion?.observation_id, "11111111-1111-4111-8111-111111111111");
  assert.equal(result.inclusion?.observed_at, "2026-08-29T11:59:58Z");
  assert.equal(result.inclusion?.leaf_hash, "d".repeat(64));
  assert.equal(result.inclusion?.log_index, 3);
  assert.equal(result.inclusion?.sth.tree_size, 8);
});

test("VerifyInclusion remains compatible when identity fields are absent", () => {
  const inclusion: VerifyInclusion = {
    tree_size: 1,
    log_index: 0,
    audit_path: [],
    sth: {
      log_id: "iff-log",
      tree_size: 1,
      timestamp: "2026-08-29T12:00:00Z",
      root_hash: "c".repeat(64),
      signature: "signature",
      public_key: "public-key",
    },
  };
  assert.equal(inclusion.observation_id, undefined);
  assert.equal(inclusion.observed_at, undefined);
  assert.equal(inclusion.leaf_hash, undefined);
});
