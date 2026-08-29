package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyPostsURLAndPaymentRequired(t *testing.T) {
	var capturedPath string
	var capturedBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Result{
			URL: "https://example.com/paid", Verdict: VerdictConsistent,
			Received: FingerprintSummary{SetFingerprint: "a", OptionFingerprints: []string{"a"}},
			History:  []RequirementHistoryEntry{}, UnmatchedReceivedOptions: []string{},
			Ownership: Ownership{Status: "verified"},
		})
	}))
	defer server.Close()

	paymentRequired := json.RawMessage(`{"x402Version":2,"accepts":[]}`)
	result, err := Verify(context.Background(), server.Client(), server.URL, "https://example.com/paid", paymentRequired)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if capturedPath != "/api/v3/verify" {
		t.Errorf("path = %s, want /api/v3/verify", capturedPath)
	}
	if string(capturedBody["url"]) != `"https://example.com/paid"` {
		t.Errorf("url in body = %s", capturedBody["url"])
	}
	if string(capturedBody["payment_required"]) != string(paymentRequired) {
		t.Errorf("payment_required in body = %s, want %s", capturedBody["payment_required"], paymentRequired)
	}
	if result.Verdict != VerdictConsistent {
		t.Errorf("verdict = %s, want %s", result.Verdict, VerdictConsistent)
	}
}

// TestVerifyDecodesMatchesLastObservedAndKnown covers the G2 2026-08-29
// amendment fields: matches_last_observed (present for every verdict
// except unobserved) and known (present only for unobserved).
func TestVerifyDecodesMatchesLastObservedAndKnown(t *testing.T) {
	mismatched := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Result{
			Verdict: VerdictStale, MatchesLastObserved: &mismatched,
			UnmatchedReceivedOptions: []string{"a"}, DivergenceKind: DivergenceKindPayee,
			History: []RequirementHistoryEntry{},
		})
	}))
	defer server.Close()

	result, err := Verify(context.Background(), server.Client(), server.URL, "https://example.com/paid", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictStale {
		t.Errorf("verdict = %s, want %s", result.Verdict, VerdictStale)
	}
	if result.MatchesLastObserved == nil || *result.MatchesLastObserved {
		t.Errorf("matches_last_observed = %v, want false", result.MatchesLastObserved)
	}
	if result.Known != nil {
		t.Errorf("known = %v, want nil (only set for unobserved)", result.Known)
	}
}

func TestVerifyDecodesKnownForUnobserved(t *testing.T) {
	known := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Result{
			Verdict: VerdictUnobserved, Known: &known,
			History: []RequirementHistoryEntry{}, UnmatchedReceivedOptions: []string{},
		})
	}))
	defer server.Close()

	result, err := Verify(context.Background(), server.Client(), server.URL, "https://example.com/paid", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Known == nil || !*result.Known {
		t.Errorf("known = %v, want true", result.Known)
	}
	if result.MatchesLastObserved != nil {
		t.Errorf("matches_last_observed = %v, want nil for unobserved", result.MatchesLastObserved)
	}
}

func TestVerifyDecodesPhase3InclusionProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"verdict":"consistent","history":[],"unmatched_received_options":[],
			"ownership":{"status":"verified"},
			"inclusion":{"observation_id":"11111111-1111-4111-8111-111111111111",
			"observed_at":"2026-08-29T11:59:58Z","leaf_hash":"leaf","tree_size":8,"log_index":3,"audit_path":["abc"],
			"sth":{"log_id":"iff-log","tree_size":8,"timestamp":"2026-08-29T12:00:00Z",
			"root_hash":"root","signature":"sig","public_key":"key"}},"disclaimer":"test"}`))
	}))
	defer server.Close()

	result, err := Verify(context.Background(), server.Client(), server.URL, "https://example.com/paid", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Inclusion == nil || result.Inclusion.LogIndex != 3 || result.Inclusion.STH.TreeSize != 8 {
		t.Fatalf("inclusion = %#v, want log_index=3 and sth.tree_size=8", result.Inclusion)
	}
	if result.Inclusion.ObservationID == nil || *result.Inclusion.ObservationID != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("inclusion observation_id = %v", result.Inclusion.ObservationID)
	}
	if result.Inclusion.ObservedAt == nil {
		t.Fatal("inclusion observed_at = nil")
	}
	if got := result.Inclusion.ObservedAt.Format(time.RFC3339); got != "2026-08-29T11:59:58Z" {
		t.Errorf("inclusion observed_at = %q", got)
	}
	if result.Inclusion.LeafHash == nil || *result.Inclusion.LeafHash != "leaf" {
		t.Errorf("inclusion leaf_hash = %v", result.Inclusion.LeafHash)
	}
}

func TestVerifyDecodesInclusionWithoutNewIdentityFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"verdict":"consistent","history":[],"unmatched_received_options":[],
			"ownership":{"status":"verified"},
			"inclusion":{"tree_size":1,"log_index":0,"audit_path":[],
			"sth":{"log_id":"iff-log","tree_size":1,"timestamp":"2026-08-29T12:00:00Z",
			"root_hash":"root","signature":"sig","public_key":"key"}},"disclaimer":"test"}`))
	}))
	defer server.Close()

	result, err := Verify(context.Background(), server.Client(), server.URL, "https://example.com/paid", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Inclusion == nil {
		t.Fatal("inclusion = nil")
	}
	if result.Inclusion.ObservationID != nil || result.Inclusion.ObservedAt != nil || result.Inclusion.LeafHash != nil {
		t.Fatalf("legacy inclusion covered-observation fields = %v, %v, %v; want nil",
			result.Inclusion.ObservationID, result.Inclusion.ObservedAt, result.Inclusion.LeafHash)
	}
}

func TestVerifyAcceptsPostsAcceptsArray(t *testing.T) {
	var capturedBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&capturedBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Result{Verdict: VerdictUnobserved, History: []RequirementHistoryEntry{}, UnmatchedReceivedOptions: []string{}})
	}))
	defer server.Close()

	accepts := json.RawMessage(`[{"scheme":"exact"}]`)
	result, err := VerifyAccepts(context.Background(), server.Client(), server.URL, "https://example.com/paid", accepts)
	if err != nil {
		t.Fatalf("VerifyAccepts: %v", err)
	}
	if _, hasPaymentRequired := capturedBody["payment_required"]; hasPaymentRequired {
		t.Error("payment_required must not be sent when only accepts is given")
	}
	if string(capturedBody["accepts"]) != string(accepts) {
		t.Errorf("accepts in body = %s, want %s", capturedBody["accepts"], accepts)
	}
	if result.Verdict != VerdictUnobserved {
		t.Errorf("verdict = %s, want %s", result.Verdict, VerdictUnobserved)
	}
}

func TestVerifyReturnsRequestErrorOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":true,"message":"invalid","check_code":"invalid_payment_option"}`))
	}))
	defer server.Close()

	_, err := Verify(context.Background(), server.Client(), server.URL, "https://example.com/paid", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected an error for a 422 response")
	}
	requestErr, ok := err.(*RequestError)
	if !ok {
		t.Fatalf("expected *RequestError, got %T: %v", err, err)
	}
	if requestErr.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want %d", requestErr.StatusCode, http.StatusUnprocessableEntity)
	}
	if !strings.Contains(string(requestErr.Body), "invalid_payment_option") {
		t.Errorf("body = %s, want it to contain invalid_payment_option", requestErr.Body)
	}
}

// stubRoundTripper intercepts requests without ever touching the network,
// so TestVerifyUsesDefaultBaseURLWhenEmpty can assert on the constructed
// request URL without making a real call to production.
type stubRoundTripper struct {
	capturedURL string
}

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.capturedURL = req.URL.String()
	body, _ := json.Marshal(Result{Verdict: VerdictConsistent, History: []RequirementHistoryEntry{}, UnmatchedReceivedOptions: []string{}})
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

func TestVerifyUsesDefaultBaseURLWhenEmpty(t *testing.T) {
	stub := &stubRoundTripper{}
	client := &http.Client{Transport: stub}
	result, err := Verify(context.Background(), client, "", "https://example.com/paid", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := DefaultBaseURL + "/api/v3/verify"
	if stub.capturedURL != want {
		t.Errorf("request URL = %s, want %s", stub.capturedURL, want)
	}
	if result.Verdict != VerdictConsistent {
		t.Errorf("verdict = %s", result.Verdict)
	}
}

func TestVerifyStripsTrailingSlashFromBaseURL(t *testing.T) {
	stub := &stubRoundTripper{}
	client := &http.Client{Transport: stub}
	if _, err := Verify(context.Background(), client, "https://staging.example/", "https://example.com/paid", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := "https://staging.example/api/v3/verify"
	if stub.capturedURL != want {
		t.Errorf("request URL = %s, want %s", stub.capturedURL, want)
	}
}

func TestVerifyNilClientDefaultsToHTTPDefaultClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Result{Verdict: VerdictConsistent, History: []RequirementHistoryEntry{}, UnmatchedReceivedOptions: []string{}})
	}))
	defer server.Close()

	result, err := Verify(context.Background(), nil, server.URL, "https://example.com/paid", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Verify with nil client: %v", err)
	}
	if result.Verdict != VerdictConsistent {
		t.Errorf("verdict = %s", result.Verdict)
	}
}
