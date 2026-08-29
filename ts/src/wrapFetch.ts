import { verify, type FetchLike, type PaymentRequiredEnvelope, type VerifyOptions, type VerifyResult } from "./verify.js";

/** How wrapFetch reacts to a "diverged" verdict. Default: "throw" -- the
 * conservative default a caller must opt out of. */
export type DivergedPolicy = "throw" | "warn" | "allow";

/** How wrapFetch reacts to a "stale" verdict (G2 4c, 2026-08-29). Default:
 * "strict" -- throw only when the stale record's own comparison window
 * (matches_last_observed) says the received requirement does NOT match;
 * otherwise (matching, or unknown because the server predates this field)
 * warn instead of throwing, since "stale" alone is not evidence of a
 * problem, just insufficient recent evidence either way. "warn" always
 * warns regardless of matches_last_observed; "allow" is always silent. */
export type StalePolicy = "strict" | "warn" | "allow";

/** How wrapFetch reacts to an "unobserved" verdict. Default: "warn" --
 * never silent by default, since paying against a URL IFF has no
 * independent evidence for at all is worth surfacing even though it is not
 * evidence of a problem either. */
export type UnobservedPolicy = "warn" | "allow";

/** Emits a one-line warning for the "warn"-resolving policies above.
 * Defaults to console.warn, so any function with console.warn's signature
 * (message: string, ...args) works as a drop-in replacement -- e.g. a
 * structured logger's `.warn` method. */
export type WrapFetchLogger = (message: string, ...args: unknown[]) => void;

export interface WrapFetchOptions {
  /** Forwarded to verify(); see VerifyOptions.baseUrl. */
  baseUrl?: string;
  /** How to react to a "diverged" verdict. Default: "throw". */
  onDiverged?: DivergedPolicy;
  /** How to react to a "stale" verdict. Default: "strict". */
  onStale?: StalePolicy;
  /** How to react to an "unobserved" verdict. Default: "warn". */
  onUnobserved?: UnobservedPolicy;
  /** Where a "warn"-resolving policy emits its message. Default:
   * console.warn. Never receives the submitted payment requirement or the
   * full request URL -- only the verdict and the URL's origin (there is no
   * query string to worry about either way: x402 v2 URLs never carry one). */
  logger?: WrapFetchLogger;
}

/** Thrown by wrapFetch when a verify() call reports "diverged" and
 * onDiverged is "throw" (the default). Carries the full VerifyResult so a
 * caller can inspect divergence_kind and unmatched_received_options. */
export class X402DivergenceError extends Error {
  readonly result: VerifyResult;

  constructor(result: VerifyResult) {
    super(
      `x402 payment requirement for ${originOf(result.url)} diverged from IFF's independent observation` +
        (result.divergence_kind ? ` (${result.divergence_kind})` : ""),
    );
    this.name = "X402DivergenceError";
    this.result = result;
  }
}

/** Thrown by wrapFetch when a verify() call reports "stale" with
 * matches_last_observed === false and onStale is "strict" (the default).
 * Distinct from X402DivergenceError because the verdict itself is "stale",
 * not "diverged" (D5's vocabulary is unchanged) -- catch both, or catch
 * Error broadly, to handle either. */
export class X402StaleMismatchError extends Error {
  readonly result: VerifyResult;

  constructor(result: VerifyResult) {
    super(
      `x402 payment requirement for ${originOf(result.url)} does not match IFF's stale (not recently refreshed) independent observation` +
        (result.divergence_kind ? ` (${result.divergence_kind})` : ""),
    );
    this.name = "X402StaleMismatchError";
    this.result = result;
  }
}

/** Reduces a URL to just its origin (scheme + host [+ port]) for logging --
 * never the path, and never the submitted payment requirement. Falls back
 * to the raw string if it does not parse as a URL (should not happen here:
 * the value always comes from a VerifyResult.url the API itself echoed
 * back after validating it). */
function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

function warn(logger: WrapFetchLogger | undefined, label: string, result: VerifyResult): void {
  (logger ?? console.warn)(`[iff-x402-preflight] ${label} for ${originOf(result.url)}`);
}

const PAYMENT_REQUIRED_HEADER_NAMES = ["PAYMENT-REQUIRED", "Payment-Required"];

function base64ToUtf8(base64: string): string {
  // atob/TextDecoder are both globals in every browser and in Node >=16 --
  // no dependency (e.g. Buffer, which is Node-only) needed.
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

/** Decodes the x402 v2 PAYMENT-REQUIRED header value (standard base64 JSON)
 * used by both the header-based and (as a fallback) JSON-body-based 402
 * response shapes. Exported for the MCP server and for direct testing. */
export function decodePaymentRequiredHeader(headerValue: string): PaymentRequiredEnvelope {
  return JSON.parse(base64ToUtf8(headerValue)) as PaymentRequiredEnvelope;
}

function readPaymentRequiredHeader(headers: Headers): string | null {
  for (const name of PAYMENT_REQUIRED_HEADER_NAMES) {
    const value = headers.get(name);
    if (value) {
      return value;
    }
  }
  return null;
}

/** Extracts the x402 v2 PaymentRequired envelope from a 402 Response, per
 * C4: the base64-encoded PAYMENT-REQUIRED header takes precedence (it is
 * the canonical x402 v2 transport), falling back to a JSON response body.
 * Returns null when neither can be decoded (e.g. a 402 from something
 * other than an x402 endpoint) -- callers must treat that as "nothing to
 * verify", not an error. */
async function extractPaymentRequired(response: Response): Promise<PaymentRequiredEnvelope | null> {
  const headerValue = readPaymentRequiredHeader(response.headers);
  if (headerValue) {
    try {
      return decodePaymentRequiredHeader(headerValue);
    } catch {
      // Fall through to the body: a malformed header is not necessarily a
      // malformed body.
    }
  }
  try {
    const body = (await response.clone().json()) as unknown;
    if (body && typeof body === "object" && Array.isArray((body as PaymentRequiredEnvelope).accepts)) {
      return body as PaymentRequiredEnvelope;
    }
  } catch {
    // Not JSON, or not the expected shape: nothing to verify.
  }
  return null;
}

function resolveRequestUrl(input: Parameters<FetchLike>[0], response: Response): string {
  // Browser fetch resolves relative inputs and redirects before producing the
  // response. Its URL is therefore both absolute and the exact endpoint that
  // returned this 402. Prefer it over the caller's possibly-relative input.
  if (response.url) {
    return response.url;
  }
  if (typeof input === "string") {
    try {
      const base = typeof globalThis.location?.href === "string" ? globalThis.location.href : undefined;
      return base ? new URL(input, base).toString() : new URL(input).toString();
    } catch {
      return input;
    }
  }
  if (input instanceof URL) {
    return input.toString();
  }
  return (input as Request).url;
}

/**
 * Wraps a fetch implementation so that any 402 response is preflight-
 * verified against IFF's independent observation (C4) before being handed
 * back to the caller. It always returns the ORIGINAL 402 response
 * untouched (its body is read via response.clone(), never consumed) so a
 * downstream payment wrapper (@x402/fetch, Cloudflare Agents'
 * withX402Client) can still proceed to actually pay -- wrapFetch only
 * observes and reacts, it never blocks the 402 itself from reaching the
 * caller.
 *
 * Defaults (G2 2026-08-29 amendment): onDiverged="throw", onStale="strict"
 * (throws only on an actual mismatch, warns otherwise), onUnobserved="warn"
 * (never silent). A "warn"-resolving policy emits through `logger`
 * (default console.warn) with only the verdict and the URL's origin --
 * never the submitted requirement, never the full URL.
 *
 * A verify() call that itself fails (network error, IFF API unavailable)
 * is treated as "cannot verify right now" and the response is passed
 * through unchanged: an IFF outage must not be able to block every x402
 * payment a caller makes. Callers who want a stricter (fail-closed)
 * posture should call verify() directly instead of using wrapFetch.
 */
export function wrapFetch(fetchImpl: FetchLike, options: WrapFetchOptions = {}): FetchLike {
  const divergedPolicy = options.onDiverged ?? "throw";
  const stalePolicy = options.onStale ?? "strict";
  const unobservedPolicy = options.onUnobserved ?? "warn";
  const verifyOptions: VerifyOptions = { baseUrl: options.baseUrl, fetch: fetchImpl };

  return (async (input, init) => {
    const response = await fetchImpl(input, init);
    if (response.status !== 402) {
      return response;
    }

    const paymentRequired = await extractPaymentRequired(response);
    if (!paymentRequired) {
      return response;
    }

    let result: VerifyResult;
    try {
      result = await verify(resolveRequestUrl(input, response), paymentRequired, verifyOptions);
    } catch {
      return response;
    }

    switch (result.verdict) {
      case "diverged":
        if (divergedPolicy === "throw") {
          throw new X402DivergenceError(result);
        }
        if (divergedPolicy === "warn") {
          warn(options.logger, "diverged", result);
        }
        break;
      case "stale": {
        const mismatched = result.matches_last_observed === false;
        if (stalePolicy === "strict") {
          if (mismatched) {
            throw new X402StaleMismatchError(result);
          }
          warn(options.logger, "stale", result);
        } else if (stalePolicy === "warn") {
          warn(options.logger, "stale", result);
        }
        break;
      }
      case "unobserved":
        if (unobservedPolicy === "warn") {
          warn(options.logger, "unobserved", result);
        }
        break;
      case "consistent":
        break;
    }

    return response;
  }) as FetchLike;
}
