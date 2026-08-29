import assert from "node:assert/strict";
import { test } from "node:test";

import { decodePaymentRequiredHeader } from "../wrapFetch.js";

test("decodePaymentRequiredHeader decodes a standard-base64 x402 v2 PAYMENT-REQUIRED value", () => {
  const paymentRequired = {
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
  const header = Buffer.from(JSON.stringify(paymentRequired), "utf8").toString("base64");
  const decoded = decodePaymentRequiredHeader(header);
  assert.deepEqual(decoded, paymentRequired);
});

test("decodePaymentRequiredHeader round-trips non-ASCII text in a description field", () => {
  const paymentRequired = {
    x402Version: 2,
    accepts: [],
    resource: { description: "支付 1 USDC 以获取訪問權" },
  };
  const header = Buffer.from(JSON.stringify(paymentRequired), "utf8").toString("base64");
  const decoded = decodePaymentRequiredHeader(header);
  assert.deepEqual(decoded, paymentRequired);
});

test("decodePaymentRequiredHeader throws on malformed base64", () => {
  assert.throws(() => decodePaymentRequiredHeader("not-base64!!!"));
});

test("decodePaymentRequiredHeader throws when the decoded content is not JSON", () => {
  const header = Buffer.from("not json", "utf8").toString("base64");
  assert.throws(() => decodePaymentRequiredHeader(header));
});
