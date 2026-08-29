import assert from "node:assert/strict";
import { test } from "node:test";

import type { FetchLike, VerifyResult } from "../verify.js";
import { X402DivergenceError, X402StaleMismatchError, wrapFetch } from "../wrapFetch.js";

function encodePaymentRequired(paymentRequired: unknown): string {
  return Buffer.from(JSON.stringify(paymentRequired), "utf8").toString("base64");
}

const SAMPLE_PAYMENT_REQUIRED = {
  x402Version: 2,
  accepts: [
    {
      scheme: "exact",
      network: "eip155:8453",
      asset: "0xab12cd34ab12cd34ab12cd34ab12cd34ab12cd34",
      amount: "1000000",
      payTo: "0xef56ab78ef56ab78ef56ab78ef56ab78ef56ab78",
      maxTimeoutSeconds: 60,
    },
  ],
};

function baseVerifyResult(verdict: VerifyResult["verdict"], matchesLastObserved?: boolean): VerifyResult {
  const mismatched = verdict === "diverged" || matchesLastObserved === false;
  return {
    url: "https://example.com/paid",
    verdict,
    received: { set_fingerprint: "a".repeat(64), option_fingerprints: ["a".repeat(64)] },
    history: [],
    unmatched_received_options: mismatched ? ["a".repeat(64)] : [],
    matches_last_observed: verdict === "unobserved" ? undefined : !mismatched,
    ownership: { status: "verified" },
    inclusion: null,
    disclaimer: "Consistency with independent observation only. Not a safety, delivery, or payment guarantee.",
  };
}

/** A minimal mock fetch: 402s the "origin" request with a PAYMENT-REQUIRED
 * header (unless overridden), and answers a POST to /api/v3/verify with the
 * given verify result/status. Tracks how many times each kind of request
 * was made, so tests can assert whether verify() was ever actually called. */
function makeMockFetch(options: {
  originHeaders?: Record<string, string>;
  originStatus?: number;
  originBody?: string;
  verifyResult?: VerifyResult;
  verifyStatus?: number;
  verifyThrows?: boolean;
  originResponseUrl?: string;
}): {
  fetch: FetchLike;
  verifyCallCount: () => number;
  originCallCount: () => number;
  submittedEndpointUrl: () => string | undefined;
} {
  let verifyCalls = 0;
  let originCalls = 0;
  let submittedEndpoint: string | undefined;
  const fetchImpl: FetchLike = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.includes("/api/v3/verify")) {
      verifyCalls++;
      if (typeof init?.body === "string") {
        submittedEndpoint = (JSON.parse(init.body) as { url?: string }).url;
      }
      if (options.verifyThrows) {
        throw new Error("network error reaching the verify API");
      }
      return new Response(JSON.stringify(options.verifyResult ?? baseVerifyResult("consistent")), {
        status: options.verifyStatus ?? 200,
        headers: { "content-type": "application/json" },
      });
    }
    originCalls++;
    const response = new Response(options.originBody ?? "", {
      status: options.originStatus ?? 402,
      headers: options.originHeaders ?? { "PAYMENT-REQUIRED": encodePaymentRequired(SAMPLE_PAYMENT_REQUIRED) },
    });
    if (options.originResponseUrl) {
      Object.defineProperty(response, "url", { value: options.originResponseUrl });
    }
    return response;
  }) as FetchLike;
  return {
    fetch: fetchImpl,
    verifyCallCount: () => verifyCalls,
    originCallCount: () => originCalls,
    submittedEndpointUrl: () => submittedEndpoint,
  };
}

test("wrapFetch passes a non-402 response through unchanged and never calls verify", async () => {
  const mock = makeMockFetch({ originStatus: 200, originHeaders: {} });
  const wrapped = wrapFetch(mock.fetch);
  const response = await wrapped("https://example.com/free");
  assert.equal(response.status, 200);
  assert.equal(mock.verifyCallCount(), 0);
});

test("wrapFetch returns the original 402 response with its body still readable (consistent verdict)", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("consistent"), originBody: '{"hello":"world"}' });
  const wrapped = wrapFetch(mock.fetch);
  const response = await wrapped("https://example.com/paid");
  assert.equal(response.status, 402);
  const body = await response.json();
  assert.deepEqual(body, { hello: "world" });
  assert.equal(mock.verifyCallCount(), 1);
});

test("wrapFetch onDiverged defaults to throw", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("diverged") });
  const wrapped = wrapFetch(mock.fetch);
  await assert.rejects(() => wrapped("https://example.com/paid"), X402DivergenceError);
});

test("wrapFetch onDiverged='warn' does not throw and logs a warning", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("diverged") });
  const wrapped = wrapFetch(mock.fetch, { onDiverged: "warn" });
  const originalWarn = console.warn;
  let warned = false;
  console.warn = () => {
    warned = true;
  };
  try {
    const response = await wrapped("https://example.com/paid");
    assert.equal(response.status, 402);
  } finally {
    console.warn = originalWarn;
  }
  assert.equal(warned, true);
});

test("wrapFetch onDiverged='allow' does not throw and does not warn", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("diverged") });
  const wrapped = wrapFetch(mock.fetch, { onDiverged: "allow" });
  const originalWarn = console.warn;
  let warned = false;
  console.warn = () => {
    warned = true;
  };
  try {
    const response = await wrapped("https://example.com/paid");
    assert.equal(response.status, 402);
  } finally {
    console.warn = originalWarn;
  }
  assert.equal(warned, false);
});

// --- onStale (G2 4c): default "strict" ---

test("wrapFetch onStale defaults to \"strict\", which warns (not throws) when matches_last_observed is true", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("stale", true) });
  let warned: string | undefined;
  const wrapped = wrapFetch(mock.fetch, { logger: (message) => (warned = message) });
  const response = await wrapped("https://example.com/paid");
  assert.equal(response.status, 402);
  assert.match(warned ?? "", /stale/);
});

test("wrapFetch onStale=\"strict\" (default) throws X402StaleMismatchError when matches_last_observed is false", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("stale", false) });
  const wrapped = wrapFetch(mock.fetch);
  await assert.rejects(() => wrapped("https://example.com/paid"), X402StaleMismatchError);
});

test("wrapFetch onStale=\"warn\" always warns, even on a mismatch, and never throws", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("stale", false) });
  let warned = false;
  const wrapped = wrapFetch(mock.fetch, { onStale: "warn", logger: () => (warned = true) });
  const response = await wrapped("https://example.com/paid");
  assert.equal(response.status, 402);
  assert.equal(warned, true);
});

test("wrapFetch onStale=\"allow\" is always silent, even on a mismatch", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("stale", false) });
  let warned = false;
  const wrapped = wrapFetch(mock.fetch, { onStale: "allow", logger: () => (warned = true) });
  const response = await wrapped("https://example.com/paid");
  assert.equal(response.status, 402);
  assert.equal(warned, false);
});

// --- onUnobserved: default "warn" (never silent) ---

test("wrapFetch onUnobserved defaults to \"warn\"", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("unobserved") });
  let warned: string | undefined;
  const wrapped = wrapFetch(mock.fetch, { logger: (message) => (warned = message) });
  const response = await wrapped("https://example.com/paid");
  assert.equal(response.status, 402);
  assert.match(warned ?? "", /unobserved/);
});

test("wrapFetch onUnobserved=\"allow\" is silent", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("unobserved") });
  let warned = false;
  const wrapped = wrapFetch(mock.fetch, { onUnobserved: "allow", logger: () => (warned = true) });
  const response = await wrapped("https://example.com/paid");
  assert.equal(response.status, 402);
  assert.equal(warned, false);
});

// --- logger: verdict + origin only, never the requirement or full URL ---

test("wrapFetch's logger receives only the verdict label and the URL's origin, never a path or the requirement", async () => {
  const mock = makeMockFetch({
    verifyResult: { ...baseVerifyResult("unobserved"), url: "https://example.com/secret/path?should-not-appear" },
  });
  let message: string | undefined;
  const wrapped = wrapFetch(mock.fetch, { logger: (m) => (message = m) });
  await wrapped("https://example.com/secret/path?should-not-appear");
  assert.ok(message);
  assert.match(message, /unobserved/);
  assert.match(message, /https:\/\/example\.com/);
  assert.doesNotMatch(message, /\/secret\/path/);
  assert.doesNotMatch(message, /should-not-appear/);
});

test("wrapFetch's default logger is console.warn", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("unobserved") });
  const originalWarn = console.warn;
  let calledWith: unknown;
  console.warn = (message: unknown) => {
    calledWith = message;
  };
  try {
    const wrapped = wrapFetch(mock.fetch);
    await wrapped("https://example.com/paid");
  } finally {
    console.warn = originalWarn;
  }
  assert.match(String(calledWith), /unobserved/);
});

test("wrapFetch falls back to a JSON response body when there is no PAYMENT-REQUIRED header", async () => {
  const mock = makeMockFetch({
    originHeaders: { "content-type": "application/json" },
    originBody: JSON.stringify(SAMPLE_PAYMENT_REQUIRED),
    verifyResult: baseVerifyResult("consistent"),
  });
  const wrapped = wrapFetch(mock.fetch);
  const response = await wrapped("https://example.com/paid");
  assert.equal(response.status, 402);
  assert.equal(mock.verifyCallCount(), 1, "a decodable JSON body must still trigger verify()");
});

test("wrapFetch falls back to the body when the PAYMENT-REQUIRED header is present but not valid base64/JSON", async () => {
  const mock = makeMockFetch({
    originHeaders: { "PAYMENT-REQUIRED": "not-valid-base64!!!", "content-type": "application/json" },
    originBody: JSON.stringify(SAMPLE_PAYMENT_REQUIRED),
    verifyResult: baseVerifyResult("consistent"),
  });
  const wrapped = wrapFetch(mock.fetch);
  const response = await wrapped("https://example.com/paid");
  assert.equal(response.status, 402);
  assert.equal(mock.verifyCallCount(), 1, "a malformed header must not prevent falling back to a decodable body");
});

test("wrapFetch passes through untouched when neither header nor a decodable body is present", async () => {
  const mock = makeMockFetch({ originHeaders: {}, originBody: "not json and no header" });
  const wrapped = wrapFetch(mock.fetch);
  const response = await wrapped("https://example.com/paid");
  assert.equal(response.status, 402);
  assert.equal(mock.verifyCallCount(), 0, "nothing to verify means verify() must never be called");
});

test("wrapFetch fails open (passes the response through) when verify() itself errors", async () => {
  const mock = makeMockFetch({ verifyThrows: true });
  const wrapped = wrapFetch(mock.fetch);
  const response = await wrapped("https://example.com/paid");
  assert.equal(response.status, 402, "an IFF API outage must not block the underlying 402 from reaching the caller");
});

test("wrapFetch resolves the request URL from a Request object input, not just a string", async () => {
  const mock = makeMockFetch({ verifyResult: baseVerifyResult("consistent") });
  const wrapped = wrapFetch(mock.fetch);
  const response = await wrapped(new Request("https://example.com/paid"));
  assert.equal(response.status, 402);
  assert.equal(mock.verifyCallCount(), 1);
});

test("wrapFetch uses response.url to resolve a browser-relative request before verification", async () => {
  const mock = makeMockFetch({
    verifyResult: baseVerifyResult("consistent"),
    originResponseUrl: "https://wallet.example/paid",
  });
  const wrapped = wrapFetch(mock.fetch);
  const response = await wrapped("/paid");
  assert.equal(response.status, 402);
  assert.equal(mock.verifyCallCount(), 1);
  assert.equal(mock.submittedEndpointUrl(), "https://wallet.example/paid");
});
