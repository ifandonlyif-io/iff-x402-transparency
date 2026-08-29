package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is IFF's production API host. Override via the baseURL
// parameter to Verify/VerifyAccepts for local or staging use.
const DefaultBaseURL = "https://ifandonlyif.io"

// maxVerifyResponseBytes bounds how much of a POST /api/v3/verify response
// body Verify will read, defending against a misbehaving or malicious
// server -- the real response is a small, fixed-shape JSON object.
const maxVerifyResponseBytes = 1 << 20 // 1 MiB

// FingerprintSummary is the fingerprint-only shape C4 uses for both
// "received" and the fingerprint half of "observed": never payTo/amount
// plaintext, only fingerprints.
type FingerprintSummary struct {
	SetFingerprint     string   `json:"set_fingerprint"`
	OptionFingerprints []string `json:"option_fingerprints"`
}

// ObservedSummary is C4's "observed" response block.
type ObservedSummary struct {
	SetFingerprint     string    `json:"set_fingerprint"`
	OptionFingerprints []string  `json:"option_fingerprints"`
	ObservationID      string    `json:"observation_id"`
	ObservedAt         time.Time `json:"observed_at"`
	ProbeType          string    `json:"probe_type"`
	MonitorID          string    `json:"monitor_id"`
	MonitorPublicKey   string    `json:"monitor_public_key"`
	ReportHash         string    `json:"report_hash"`
	MonitorSignature   string    `json:"monitor_signature"`
}

// RequirementHistoryEntry is one run in C4's "history" array.
type RequirementHistoryEntry struct {
	SetFingerprint string    `json:"set_fingerprint"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	Observations   int64     `json:"observations"`
}

// Ownership is C4's "ownership" response block.
type Ownership struct {
	Status         string     `json:"status"`
	Method         string     `json:"method,omitempty"`
	VerifiedAt     *time.Time `json:"verified_at,omitempty"`
	LastVerifiedAt *time.Time `json:"last_verified_at,omitempty"`
}

// InclusionSTH is the signed tree head embedded with a Phase 3 proof.
type InclusionSTH struct {
	LogID     string    `json:"log_id"`
	TreeSize  int64     `json:"tree_size"`
	Timestamp time.Time `json:"timestamp"`
	RootHash  string    `json:"root_hash"`
	Signature string    `json:"signature"`
	PublicKey string    `json:"public_key"`
}

// Inclusion proves the newest observation for this endpoint covered by the
// latest signed tree head. ObservationID may differ from Result.Observed;
// ObservationID, ObservedAt, and LeafHash are optional for compatibility
// with servers deployed before those covered-observation fields were added.
type Inclusion struct {
	ObservationID *string      `json:"observation_id,omitempty"`
	ObservedAt    *time.Time   `json:"observed_at,omitempty"`
	LeafHash      *string      `json:"leaf_hash,omitempty"`
	TreeSize      int64        `json:"tree_size"`
	LogIndex      int64        `json:"log_index"`
	AuditPath     []string     `json:"audit_path"`
	STH           InclusionSTH `json:"sth"`
}

// Result is POST /api/v3/verify's exact response shape (C4, amended G2
// 2026-08-29 4c). Field names and JSON tags mirror the API contract (and
// api.VerifyResponse in the root module) verbatim; this type is a
// standalone copy because this module has no dependency on the root
// module.
type Result struct {
	URL                      string                    `json:"url"`
	Verdict                  string                    `json:"verdict"`
	Tier                     string                    `json:"tier,omitempty"`
	Received                 FingerprintSummary        `json:"received"`
	Observed                 *ObservedSummary          `json:"observed,omitempty"`
	WindowSeconds            int64                     `json:"window_seconds,omitempty"`
	History                  []RequirementHistoryEntry `json:"history"`
	StableSince              *time.Time                `json:"stable_since,omitempty"`
	UnmatchedReceivedOptions []string                  `json:"unmatched_received_options"`
	DivergenceKind           string                    `json:"divergence_kind,omitempty"`
	// MatchesLastObserved is set (G2 4c) for every verdict except
	// "unobserved": true when every received option fingerprint is in the
	// comparison window's union. For "stale" this is the only signal
	// distinguishing a stale-but-matching endpoint from a stale-and-
	// diverged one, since the verdict itself stays "stale" either way (D5).
	MatchesLastObserved *bool     `json:"matches_last_observed,omitempty"`
	Ownership           Ownership `json:"ownership"`
	// Known is set (G2) only for verdict "unobserved": true when an
	// endpoint row exists but has never produced a fingerprint observation,
	// false when the URL has never been seen as an endpoint at all.
	Known *bool `json:"known,omitempty"`
	// Inclusion is nil until this endpoint has an observation covered by an STH.
	Inclusion  *Inclusion `json:"inclusion"`
	Disclaimer string     `json:"disclaimer"`
}

// C4's fixed verdict vocabulary (D5): never safe/unsafe/score.
const (
	VerdictConsistent = "consistent"
	VerdictDiverged   = "diverged"
	VerdictUnobserved = "unobserved"
	VerdictStale      = "stale"
)

// C4 rule 4b's divergence classification.
const (
	DivergenceKindAmountOnly = "amount_only"
	DivergenceKindPayee      = "payee"
)

// RequestError is returned when POST /api/v3/verify itself responds with a
// non-2xx status (400/413/422/429/5xx). Body is the raw response body
// (typically a small JSON error object carrying a "check_code").
type RequestError struct {
	StatusCode int
	Body       []byte
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("verify request failed with status %d: %s", e.StatusCode, string(e.Body))
}

type verifyRequestBody struct {
	URL             string          `json:"url"`
	PaymentRequired json.RawMessage `json:"payment_required,omitempty"`
	Accepts         json.RawMessage `json:"accepts,omitempty"`
}

// Verify calls POST /api/v3/verify (docs/TRANSPARENCY_LOG_PLAN.md, C4) with
// a full x402 v2 PaymentRequired JSON: given the URL an agent/wallet is
// about to pay and the requirement it received, reports whether that
// requirement is consistent with IFF's independent, signed observation.
// Never probes the URL itself.
//
// client may be nil, in which case http.DefaultClient is used. baseURL may
// be empty, in which case DefaultBaseURL is used. paymentRequiredJSON must
// be the raw x402 v2 PaymentRequired JSON (e.g. the decoded PAYMENT-REQUIRED
// header, or a response body) -- exactly what the "payment_required" field
// of the verify request expects.
func Verify(
	ctx context.Context, client *http.Client, baseURL, url string, paymentRequiredJSON json.RawMessage,
) (*Result, error) {
	return doVerify(ctx, client, baseURL, verifyRequestBody{URL: url, PaymentRequired: paymentRequiredJSON})
}

// VerifyAccepts calls POST /api/v3/verify with a bare "accepts" array (C4's
// alternative request shape), for a caller that only has the array and not
// a full PaymentRequired envelope.
func VerifyAccepts(
	ctx context.Context, client *http.Client, baseURL, url string, acceptsJSON json.RawMessage,
) (*Result, error) {
	return doVerify(ctx, client, baseURL, verifyRequestBody{URL: url, Accepts: acceptsJSON})
}

func doVerify(ctx context.Context, client *http.Client, baseURL string, requestBody verifyRequestBody) (*Result, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal verify request: %w", err)
	}

	endpoint := strings.TrimRight(baseURL, "/") + "/api/v3/verify"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build verify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("verify request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVerifyResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read verify response: %w", err)
	}
	if len(body) > maxVerifyResponseBytes {
		return nil, fmt.Errorf("verify response exceeded %d bytes", maxVerifyResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &RequestError{StatusCode: resp.StatusCode, Body: body}
	}

	var result Result
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode verify response: %w", err)
	}
	return &result, nil
}
