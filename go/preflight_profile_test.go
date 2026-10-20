package preflight

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyDecodesObservedProfileAndLegacyResponses(t *testing.T) {
	const openingID = "11111111-1111-4111-8111-111111111111"
	const olderID = "22222222-2222-4222-8222-222222222222"
	const opening = `"observed":{"observation_id":"` + openingID + `","observed_at":"2026-10-01T10:00:00Z"`
	const inclusion = `"inclusion":{"observation_id":"` + openingID + `","observed_at":"2026-10-01T10:00:00Z","tree_size":1,"log_index":0,"audit_path":[]}`
	const olderInclusion = `"inclusion":{"observation_id":"` + olderID + `","observed_at":"2026-10-01T09:00:00Z","tree_size":1,"log_index":0,"audit_path":[]}`
	cases := []struct {
		name, response, policy, reason, confirmed, attempt, outcome, episodeConfirmed, inclusionID string
	}{
		{
			name: "observed episode opening and repeat confirmation",
			response: `{"verdict":"consistent","tier":"observed","comparison_policy":"observed-confirmation-window/v1",` +
				`"last_confirmed_at":"2026-10-01T11:00:00Z","last_attempt_at":"2026-10-01T11:05:00Z","last_attempt_outcome":"no_information",` +
				opening + `,"last_confirmed_at":"2026-10-01T11:00:00Z"},` + inclusion + `}`,
			policy: "observed-confirmation-window/v1", confirmed: "2026-10-01T11:00:00Z",
			attempt: "2026-10-01T11:05:00Z", outcome: "no_information",
			episodeConfirmed: "2026-10-01T11:00:00Z", inclusionID: openingID,
		},
		{
			name: "observed current requirements unavailable without covered opening",
			response: `{"verdict":"stale","tier":"observed","comparison_policy":"observed-confirmation-window/v1",` +
				`"freshness_reason":"current_requirements_unavailable","last_confirmed_at":"2026-10-01T11:00:00Z",` +
				`"last_attempt_at":"2026-10-01T11:05:00Z","last_attempt_outcome":"non_402",` +
				opening + `,"last_confirmed_at":"2026-10-01T11:00:00Z"},"inclusion":null}`,
			policy: "observed-confirmation-window/v1", reason: "current_requirements_unavailable",
			confirmed: "2026-10-01T11:00:00Z", attempt: "2026-10-01T11:05:00Z", outcome: "non_402",
			episodeConfirmed: "2026-10-01T11:00:00Z",
		},
		{
			name: "verified profile retains older covered observation",
			response: `{"verdict":"consistent","tier":"verified","comparison_policy":"observation-window/v1",` +
				`"last_confirmed_at":"2026-10-01T10:00:00Z","last_attempt_at":"2026-10-01T10:00:00Z","last_attempt_outcome":"valid_requirements",` +
				opening + `},` + olderInclusion + `}`,
			policy: "observation-window/v1", confirmed: "2026-10-01T10:00:00Z",
			attempt: "2026-10-01T10:00:00Z", outcome: "valid_requirements", inclusionID: olderID,
		},
		{
			name:     "legacy response omits all profile fields",
			response: `{"verdict":"consistent",` + opening + `},"inclusion":null}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.response))
			}))
			defer server.Close()
			result, err := Verify(context.Background(), server.Client(), server.URL, "https://example.com/paid", json.RawMessage(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if result.ComparisonPolicy != tc.policy || result.FreshnessReason != tc.reason || result.LastAttemptOutcome != tc.outcome {
				t.Fatalf("profile fields = %q/%q/%q, want %q/%q/%q", result.ComparisonPolicy, result.FreshnessReason,
					result.LastAttemptOutcome, tc.policy, tc.reason, tc.outcome)
			}
			assertProfileTime(t, "last_confirmed_at", result.LastConfirmedAt, tc.confirmed)
			assertProfileTime(t, "last_attempt_at", result.LastAttemptAt, tc.attempt)
			if result.Observed == nil || result.Observed.ObservationID != openingID || result.Observed.ObservedAt.Format(time.RFC3339) != "2026-10-01T10:00:00Z" {
				t.Fatalf("observed opening = %+v", result.Observed)
			}
			assertProfileTime(t, "observed.last_confirmed_at", result.Observed.LastConfirmedAt, tc.episodeConfirmed)
			if tc.inclusionID == "" {
				if result.Inclusion != nil {
					t.Fatalf("inclusion = %+v, want nil", result.Inclusion)
				}
			} else if result.Inclusion == nil || result.Inclusion.ObservationID == nil || *result.Inclusion.ObservationID != tc.inclusionID {
				t.Fatalf("inclusion = %+v, want observation %s", result.Inclusion, tc.inclusionID)
			}
		})
	}
}

func assertProfileTime(t *testing.T, name string, got *time.Time, want string) {
	t.Helper()
	if want == "" {
		if got != nil {
			t.Fatalf("%s = %s, want absent", name, got)
		}
		return
	}
	if got == nil || got.Format(time.RFC3339) != want {
		t.Fatalf("%s = %v, want %s", name, got, want)
	}
}
