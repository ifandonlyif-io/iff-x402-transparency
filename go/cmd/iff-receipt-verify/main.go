// iff-receipt-verify is an offline Service Receipt v1 verifier. The command
// and the receipt package it calls use only the Go standard library.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ifandonlyif-io/iff-x402-transparency/go/receipt"
)

const maxInputBytes = 256 << 10

type output struct {
	ReceiptID           string `json:"receipt_id"`
	Issuer              string `json:"issuer"`
	Service             string `json:"service"`
	KeyID               string `json:"key_id"`
	PayloadSHA256       string `json:"payload_sha256"`
	SignatureValid      bool   `json:"signature_valid"`
	IssuerTrusted       bool   `json:"issuer_trusted"`
	Expired             bool   `json:"expired"`
	NotYetValid         bool   `json:"not_yet_valid"`
	SubjectMatchesOuter *bool  `json:"subject_matches_outer,omitempty"`
	EvidenceStatus      string `json:"evidence_status"`
	ComputeProofStatus  string `json:"compute_proof_status"`
}

func main() {
	file := flag.String("file", "-", "receipt envelope or full API response JSON file; - reads stdin")
	expectedIssuer := flag.String("expected-issuer", "", "exact issuer origin required for issuer_trusted")
	trustedKeyIDs := flag.String("trusted-key-id", "", "comma-separated full sha256: public-key fingerprints")
	requireTrust := flag.Bool("require-trust", false, "exit non-zero unless issuer and a trusted key ID both match")
	printSubject := flag.Bool("print-subject", false, "write the signed JSON subject after the verification summary")
	flag.Parse()

	raw, err := readBounded(*file)
	if err != nil {
		fail(2, err)
	}
	envelopeRaw, outerRaw, err := extractEnvelope(raw)
	if err != nil {
		fail(2, err)
	}
	verification, err := receipt.VerifyJSON(envelopeRaw, receipt.VerifyOptions{
		TrustedKeyIDs: splitNonEmpty(*trustedKeyIDs), ExpectedIssuer: *expectedIssuer,
		Now: time.Now(),
	})
	if err != nil {
		fail(2, err)
	}

	var subjectMatches *bool
	if outerRaw != nil {
		matches := verification.SubjectMatchesJSON(outerRaw)
		subjectMatches = &matches
	}
	encoded, err := json.MarshalIndent(output{
		ReceiptID: verification.Payload.ReceiptID, Issuer: verification.Payload.Issuer,
		Service: verification.Payload.Service, KeyID: verification.KeyID, PayloadSHA256: verification.PayloadSHA256,
		SignatureValid: verification.SignatureValid, IssuerTrusted: verification.IssuerTrusted,
		Expired: verification.Expired, NotYetValid: verification.NotYetValid,
		SubjectMatchesOuter: subjectMatches, EvidenceStatus: verification.EvidenceStatus,
		ComputeProofStatus: verification.ComputeProofStatus,
	}, "", "  ")
	if err != nil {
		fail(2, err)
	}
	fmt.Println(string(encoded))
	if *printSubject {
		fmt.Println(string(verification.Subject))
	}
	if subjectMatches != nil && !*subjectMatches {
		fail(4, fmt.Errorf("outer response does not match the signed subject"))
	}
	if *requireTrust && !verification.IssuerTrusted {
		fail(3, fmt.Errorf("issuer trust policy did not match"))
	}
}

func readBounded(path string) ([]byte, error) {
	var reader io.Reader = os.Stdin
	var file *os.File
	if path != "-" {
		opened, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		file = opened
		defer file.Close()
		reader = file
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxInputBytes {
		return nil, fmt.Errorf("input must contain 1-%d bytes", maxInputBytes)
	}
	return raw, nil
}

func extractEnvelope(raw []byte) (envelopeRaw, outerRaw []byte, err error) {
	if err := receipt.ValidateUniqueJSON(raw); err != nil {
		return nil, nil, fmt.Errorf("parse input JSON: %w", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, nil, fmt.Errorf("parse input JSON: %w", err)
	}
	if embedded, ok := object["service_receipt"]; ok {
		delete(object, "service_receipt")
		outer, marshalErr := json.Marshal(object)
		if marshalErr != nil {
			return nil, nil, marshalErr
		}
		return embedded, outer, nil
	}
	return raw, nil, nil
}

func splitNonEmpty(raw string) []string {
	values := make([]string, 0)
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func fail(code int, err error) {
	fmt.Fprintln(os.Stderr, "iff-receipt-verify:", err)
	os.Exit(code)
}
