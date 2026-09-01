package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ifandonlyif-io/iff-x402-transparency/go/receipt"
)

func vectorEnvelope(t *testing.T) (receipt.Envelope, string) {
	t.Helper()
	var vector struct {
		CanonicalSubject string `json:"canonical_subject"`
		Valid            struct {
			Envelope receipt.Envelope `json:"envelope"`
		} `json:"valid"`
	}
	raw, err := os.ReadFile("../../../spec/testdata/service_receipt_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector.Valid.Envelope, vector.CanonicalSubject
}

func TestExtractEnvelopeSupportsStandaloneAndMatchingOuterResponse(t *testing.T) {
	envelope, subject := vectorEnvelope(t)
	envelopeRaw, _ := json.Marshal(envelope)
	extracted, outer, err := extractEnvelope(envelopeRaw)
	if err != nil || outer != nil || string(extracted) != string(envelopeRaw) {
		t.Fatalf("standalone extraction failed: outer=%s err=%v", outer, err)
	}

	var outerObject map[string]json.RawMessage
	if err := json.Unmarshal([]byte(subject), &outerObject); err != nil {
		t.Fatal(err)
	}
	outerObject["service_receipt"] = envelopeRaw
	fullRaw, _ := json.Marshal(outerObject)
	extracted, outer, err = extractEnvelope(fullRaw)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := receipt.VerifyJSON(extracted, receipt.VerifyOptions{
		Now: time.Date(2026, 9, 1, 3, 6, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.SubjectMatchesJSON(outer) {
		t.Fatal("matching full response must match its signed subject")
	}

	outerObject["verdict"] = json.RawMessage(`"consistent"`)
	fullRaw, _ = json.Marshal(outerObject)
	extracted, outer, err = extractEnvelope(fullRaw)
	if err != nil {
		t.Fatal(err)
	}
	verified, err = receipt.VerifyJSON(extracted, receipt.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if verified.SubjectMatchesJSON(outer) {
		t.Fatal("substituted outer verdict must not match")
	}
}

func TestExtractEnvelopeRejectsDuplicateOuterFields(t *testing.T) {
	envelope, _ := vectorEnvelope(t)
	envelopeRaw, _ := json.Marshal(envelope)
	duplicated := append([]byte(`{"service_receipt":`), envelopeRaw...)
	duplicated = append(duplicated, []byte(`,"service_receipt":`)...)
	duplicated = append(duplicated, envelopeRaw...)
	duplicated = append(duplicated, '}')
	if _, _, err := extractEnvelope(duplicated); err == nil {
		t.Fatal("duplicate outer service_receipt must fail")
	}

	nestedDuplicate := append([]byte(`{"result":{"value":1,"value":2},"service_receipt":`), envelopeRaw...)
	nestedDuplicate = append(nestedDuplicate, '}')
	if _, _, err := extractEnvelope(nestedDuplicate); err == nil {
		t.Fatal("duplicate keys anywhere in the outer response must fail")
	}
}

func TestSplitNonEmptyNormalizesCommaSeparatedPins(t *testing.T) {
	values := splitNonEmpty(" first, ,second ")
	if len(values) != 2 || values[0] != "first" || values[1] != "second" {
		t.Fatalf("unexpected split result: %#v", values)
	}
}
