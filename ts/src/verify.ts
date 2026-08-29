// Client for IFF's public POST /api/v3/verify endpoint.

/** The x402 v2 PAYMENT-REQUIRED envelope shape, as sent to
 * POST /api/v3/verify's `payment_required` field (or use `accepts` alone
 * via verifyAccepts). Intentionally typed loosely (`unknown` fields beyond
 * x402Version/accepts are fine): this SDK does not re-validate the
 * requirement client-side, the API does that with the same official-SDK
 * logic the probe path uses. */
export interface PaymentRequiredEnvelope {
  x402Version: number;
  accepts: unknown[];
  [key: string]: unknown;
}

/** DEFAULT_BASE_URL is IFF's production API host. Override via
 * VerifyOptions.baseUrl for local or staging use. */
export const DEFAULT_BASE_URL = "https://ifandonlyif.io";

export type FetchLike = typeof fetch;

export interface VerifyOptions {
  /** API base URL; defaults to DEFAULT_BASE_URL. */
  baseUrl?: string;
  /** Injectable fetch implementation, for testing or a non-standard
   * environment; defaults to globalThis.fetch. */
  fetch?: FetchLike;
}

/** C4's fixed verdict vocabulary (D5): never safe/unsafe/score. */
export type VerifyVerdict = "consistent" | "diverged" | "unobserved" | "stale";

/** C4 rule 4b's divergence classification. */
export type DivergenceKind = "amount_only" | "payee";

export interface VerifyFingerprintSummary {
  set_fingerprint: string;
  option_fingerprints: string[];
}

export interface VerifyObservedSummary extends VerifyFingerprintSummary {
  observation_id: string;
  observed_at: string;
  probe_type: string;
  monitor_id: string;
  monitor_public_key: string;
  report_hash: string;
  monitor_signature: string;
}

export interface VerifyRequirementHistoryEntry {
  set_fingerprint: string;
  first_seen: string;
  last_seen: string;
  observations: number;
}

export interface VerifyOwnership {
  status: string;
  method?: string;
  verified_at?: string;
  last_verified_at?: string;
}

export interface VerifyInclusionSTH {
  log_id: string;
  tree_size: number;
  timestamp: string;
  root_hash: string;
  signature: string;
  public_key: string;
}

export interface VerifyInclusion {
  /** Optional for compatibility with servers deployed before the covered
   * observation fields were added to this block. */
  observation_id?: string;
  observed_at?: string;
  /** RFC 6962 leaf proven by audit_path; allows verification without
   * fetching the corresponding log entry separately. */
  leaf_hash?: string;
  tree_size: number;
  log_index: number;
  audit_path: string[];
  sth: VerifyInclusionSTH;
}

/** POST /api/v3/verify's exact response shape (C4, amended G2 2026-08-29 4c).
 * Field names match the wire JSON verbatim (snake_case), not remapped to
 * camelCase, so this type stays a direct, low-risk mirror of the API
 * contract. */
export interface VerifyResult {
  url: string;
  verdict: VerifyVerdict;
  tier?: string;
  received: VerifyFingerprintSummary;
  observed?: VerifyObservedSummary;
  window_seconds?: number;
  history: VerifyRequirementHistoryEntry[];
  stable_since?: string;
  unmatched_received_options: string[];
  divergence_kind?: DivergenceKind;
  /** G2 4c: present for every verdict except "unobserved". True when every
   * received option fingerprint is in the comparison window's union. For
   * "stale" this is the only signal distinguishing a stale-but-matching
   * endpoint from a stale-and-diverged one -- the verdict itself stays
   * "stale" either way (D5's vocabulary is unchanged). */
  matches_last_observed?: boolean;
  ownership: VerifyOwnership;
  /** G2: present only for verdict "unobserved". True when an endpoint row
   * exists but has never produced a fingerprint observation, false when the
   * URL has never been seen as an endpoint at all. */
  known?: boolean;
  /** The newest observation for this endpoint covered by the latest signed
   * tree head. Its observation_id may differ from observed.observation_id. */
  inclusion: VerifyInclusion | null;
  disclaimer: string;
}

/** Thrown when POST /api/v3/verify itself returns a non-2xx response
 * (400/413/422/429/5xx). `body` is the parsed JSON error body when the
 * response was JSON, or the raw response text otherwise. */
export class VerifyRequestError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, body: unknown) {
    super(`verify request failed with status ${status}`);
    this.name = "VerifyRequestError";
    this.status = status;
    this.body = body;
  }
}

function resolveFetch(fetchImpl: FetchLike | undefined): FetchLike {
  const resolved = fetchImpl ?? (globalThis.fetch as FetchLike | undefined);
  if (!resolved) {
    throw new Error(
      "no fetch implementation available: pass options.fetch, or run in an environment with a global fetch",
    );
  }
  return resolved;
}

function resolveBaseUrl(baseUrl: string | undefined): string {
  return (baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
}

async function postVerify(baseUrl: string, fetchImpl: FetchLike, requestBody: Record<string, unknown>): Promise<VerifyResult> {
  const response = await fetchImpl(`${baseUrl}/api/v3/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(requestBody),
  });
  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = text.length > 0 ? JSON.parse(text) : undefined;
  } catch {
    parsed = text;
  }
  if (!response.ok) {
    throw new VerifyRequestError(response.status, parsed);
  }
  return parsed as VerifyResult;
}

/**
 * Calls POST /api/v3/verify with a full x402 v2 PaymentRequired envelope:
 * given the URL an agent/wallet is about to pay and the requirement it
 * received, reports whether that
 * requirement is consistent with IFF's independent, signed observation.
 * Never probes the URL itself.
 */
export async function verify(
  url: string,
  paymentRequired: PaymentRequiredEnvelope,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const fetchImpl = resolveFetch(options.fetch);
  const baseUrl = resolveBaseUrl(options.baseUrl);
  return postVerify(baseUrl, fetchImpl, { url, payment_required: paymentRequired });
}

/**
 * Calls POST /api/v3/verify with a bare `accepts` array, for a caller that
 * only has the array and not a full
 * PaymentRequired envelope.
 */
export async function verifyAccepts(url: string, accepts: unknown[], options: VerifyOptions = {}): Promise<VerifyResult> {
  const fetchImpl = resolveFetch(options.fetch);
  const baseUrl = resolveBaseUrl(options.baseUrl);
  return postVerify(baseUrl, fetchImpl, { url, accepts });
}
