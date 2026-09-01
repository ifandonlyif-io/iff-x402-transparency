package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const testSeedBase64 = "sK7iZeerLXZ6bgq6EKUTss541HL4SyUu7UxmVj9fClM="

func testPayload(t testing.TB) Payload {
	t.Helper()
	request := []byte(`{"url":"https://api.example.com/paid","received":{"set_fingerprint":"` + strings.Repeat("11", 32) + `","option_fingerprints":[]}}`)
	subject := []byte(`{"url":"https://api.example.com/paid","verdict":"unobserved","received":{"set_fingerprint":"` + strings.Repeat("11", 32) + `","option_fingerprints":[]},"history":[],"unmatched_received_options":[],"ownership":{"status":"unverified"},"known":false,"inclusion":null,"disclaimer":"Consistency with independent observation only. Not a safety, delivery, or payment guarantee."}`)
	requestHash := RequestHash(request)
	subjectHash := SubjectHash(subject)
	nonce := "checkout_7f3a"
	return Payload{
		Schema:           Schema,
		ReceiptID:        "sr1_AAECAwQFBgcICQoLDA0ODxAR",
		Issuer:           "https://ifandonlyif.io",
		Service:          "x402-requirement-verification",
		IssuedAt:         "2026-09-01T03:04:05.000000Z",
		ExpiresAt:        "2026-09-01T03:09:05.000000Z",
		Nonce:            &nonce,
		RequestSHA256:    hex.EncodeToString(requestHash[:]),
		SubjectMediaType: "application/json",
		SubjectSHA256:    hex.EncodeToString(subjectHash[:]),
		Subject:          base64.RawURLEncoding.EncodeToString(subject),
		Evidence:         nil,
		ComputeProof:     nil,
	}
}

func testSigner(t testing.TB) *Signer {
	t.Helper()
	signer, err := NewSigner(testSeedBase64)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func signRawPayload(t *testing.T, signer *Signer, payloadBytes []byte, domain string) Envelope {
	t.Helper()
	payloadHash := sha256.Sum256(payloadBytes)
	input := append([]byte(domain), payloadBytes...)
	digest := sha256.Sum256(input)
	return Envelope{
		Schema:        Schema,
		Payload:       base64.RawURLEncoding.EncodeToString(payloadBytes),
		PayloadSHA256: hex.EncodeToString(payloadHash[:]),
		Signature: Signature{
			Algorithm: Algorithm,
			KeyID:     signer.KeyID(),
			PublicKey: signer.PublicKeyBase64URL(),
			Value:     base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.privateKey, digest[:])),
		},
	}
}

func validEvidenceBinding(t *testing.T) *EvidenceBinding {
	t.Helper()
	reportHash := strings.Repeat("42", sha256.Size)
	reportBytes, err := hex.DecodeString(reportHash)
	if err != nil {
		t.Fatal(err)
	}
	leafHash := sha256.Sum256(append([]byte{0}, reportBytes...))
	return &EvidenceBinding{
		ObservationID: "00000000-0000-4000-8000-000000000001",
		ReportHash:    reportHash,
		LeafHash:      hex.EncodeToString(leafHash[:]),
		LogID:         strings.Repeat("ab", 16),
		LogIndex:      "5",
		TreeSize:      "8",
		STHRootHash:   strings.Repeat("55", sha256.Size),
		STHSHA256Hash: strings.Repeat("66", sha256.Size),
	}
}

func TestSignAndVerifySeparatesIntegrityTrustAndFreshness(t *testing.T) {
	signer := testSigner(t)
	envelope, err := signer.Sign(testPayload(t))
	if err != nil {
		t.Fatal(err)
	}

	verification, err := Verify(envelope, VerifyOptions{
		TrustedKeyIDs:  []string{signer.KeyID()},
		ExpectedIssuer: "https://ifandonlyif.io",
		Now:            time.Date(2026, 9, 1, 3, 6, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.SignatureValid || !verification.IssuerTrusted {
		t.Fatalf("expected valid trusted signature: %+v", verification)
	}
	if verification.Expired || verification.NotYetValid {
		t.Fatalf("expected receipt in its action window: %+v", verification)
	}
	if verification.ComputeProofStatus != "absent" {
		t.Fatalf("unexpected compute proof state %q", verification.ComputeProofStatus)
	}
	if !json.Valid(verification.Subject) {
		t.Fatal("verified subject must remain JSON")
	}

	for _, testCase := range []struct {
		name    string
		options VerifyOptions
	}{
		{
			name: "matching_issuer_without_independent_key_pin",
			options: VerifyOptions{
				ExpectedIssuer: "https://ifandonlyif.io",
				Now:            time.Date(2026, 9, 1, 3, 6, 0, 0, time.UTC),
			},
		},
		{
			name: "key_pin_without_expected_issuer",
			options: VerifyOptions{
				TrustedKeyIDs: []string{signer.KeyID()},
				Now:           time.Date(2026, 9, 1, 3, 6, 0, 0, time.UTC),
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			selfConsistentOnly, err := Verify(envelope, testCase.options)
			if err != nil {
				t.Fatal(err)
			}
			if !selfConsistentOnly.SignatureValid || selfConsistentOnly.IssuerTrusted {
				t.Fatalf("issuer trust must require both exact issuer and an independent key pin: %+v", selfConsistentOnly)
			}
		})
	}

	untrusted, err := Verify(envelope, VerifyOptions{
		TrustedKeyIDs: []string{signer.KeyID()}, ExpectedIssuer: "https://other.example",
		Now: time.Date(2026, 9, 1, 3, 10, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !untrusted.SignatureValid || untrusted.IssuerTrusted || !untrusted.Expired {
		t.Fatalf("embedded key must not imply issuer trust and expiry must be independent: %+v", untrusted)
	}
}

func TestVerifyRejectsTamperingAndNonCanonicalPayload(t *testing.T) {
	signer := testSigner(t)
	envelope, err := signer.Sign(testPayload(t))
	if err != nil {
		t.Fatal(err)
	}

	tampered := envelope
	tampered.PayloadSHA256 = strings.Repeat("00", sha256.Size)
	if _, err := Verify(tampered, VerifyOptions{}); err == nil {
		t.Fatal("tampered payload hash must fail")
	}

	tampered = envelope
	signature, _ := base64.RawURLEncoding.DecodeString(tampered.Signature.Value)
	signature[0] ^= 0xff
	tampered.Signature.Value = base64.RawURLEncoding.EncodeToString(signature)
	if _, err := Verify(tampered, VerifyOptions{}); err == nil {
		t.Fatal("tampered signature must fail")
	}

	// A differently formatted payload can be signed correctly, but v1 still
	// rejects it because canonical fixed-order JSON is part of the contract.
	payloadBytes, _ := json.MarshalIndent(testPayload(t), "", "  ")
	payloadHash := sha256.Sum256(payloadBytes)
	digest := signingDigest(payloadBytes)
	privateKey := signer.privateKey
	nonCanonical := Envelope{
		Schema:        Schema,
		Payload:       base64.RawURLEncoding.EncodeToString(payloadBytes),
		PayloadSHA256: hex.EncodeToString(payloadHash[:]),
		Signature: Signature{
			Algorithm: Algorithm,
			KeyID:     signer.KeyID(),
			PublicKey: signer.PublicKeyBase64URL(),
			Value:     base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, digest[:])),
		},
	}
	if _, err := Verify(nonCanonical, VerifyOptions{}); err == nil {
		t.Fatal("non-canonical signed payload must fail")
	}
}

func TestVerifyJSONRejectsUnknownFields(t *testing.T) {
	signer := testSigner(t)
	envelope, err := signer.Sign(testPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope)
	raw = append(raw[:len(raw)-1], []byte(`,"unexpected":true}`)...)
	if _, err := VerifyJSON(raw, VerifyOptions{}); err == nil {
		t.Fatal("unknown envelope fields must fail")
	}
}

func TestVerifyRejectsSignatureFromDifferentDomain(t *testing.T) {
	signer := testSigner(t)
	payloadBytes, err := json.Marshal(testPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	envelope := signRawPayload(t, signer, payloadBytes, "another-protocol/v1\n")
	if _, err := Verify(envelope, VerifyOptions{}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("signature from another domain must fail as an invalid signature, got %v", err)
	}
}

func TestVerifyJSONRejectsSignedDuplicateKeysAtEverySignedLayer(t *testing.T) {
	signer := testSigner(t)
	envelope, err := signer.Sign(testPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	duplicateSignature := strings.Replace(
		string(envelopeRaw),
		`"algorithm":"Ed25519"`,
		`"algorithm":"Ed25519","algorithm":"Ed25519"`,
		1,
	)
	if _, err := VerifyJSON([]byte(duplicateSignature), VerifyOptions{}); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("duplicate signature key must fail as an invalid envelope, got %v", err)
	}

	payloadRaw, err := json.Marshal(testPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	duplicatePayload := strings.Replace(
		string(payloadRaw),
		`"service":"x402-requirement-verification"`,
		`"service":"x402-requirement-verification","service":"x402-requirement-verification"`,
		1,
	)
	signedDuplicatePayload := signRawPayload(t, signer, []byte(duplicatePayload), Domain)
	if _, err := Verify(signedDuplicatePayload, VerifyOptions{}); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("signed duplicate payload key must fail as an invalid payload, got %v", err)
	}

	duplicateSubject := []byte(`{"value":1,"value":2}`)
	payload := testPayload(t)
	subjectHash := SubjectHash(duplicateSubject)
	payload.Subject = base64.RawURLEncoding.EncodeToString(duplicateSubject)
	payload.SubjectSHA256 = hex.EncodeToString(subjectHash[:])
	duplicateSubjectPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signedDuplicateSubject := signRawPayload(t, signer, duplicateSubjectPayload, Domain)
	if _, err := Verify(signedDuplicateSubject, VerifyOptions{}); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("signed duplicate subject key must fail as an invalid payload, got %v", err)
	}
}

func TestVerifyRejectsNonCanonicalBase64URLAndPropertyCase(t *testing.T) {
	signer := testSigner(t)
	envelope, err := signer.Sign(testPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	encoded := envelope.Signature.PublicKey // 32 bytes => two unused trailing bits.
	index := strings.IndexByte(alphabet, encoded[len(encoded)-1])
	if index < 0 || index&3 != 0 {
		t.Fatalf("unexpected canonical trailing sextet %q", encoded[len(encoded)-1])
	}
	nonCanonical := envelope
	nonCanonical.Signature.PublicKey = encoded[:len(encoded)-1] + string(alphabet[index+1])
	if _, err := Verify(nonCanonical, VerifyOptions{}); err == nil {
		t.Fatal("non-zero base64url trailing pad bits must fail")
	}

	raw, _ := json.Marshal(envelope)
	raw = []byte(strings.Replace(string(raw), `"schema":`, `"Schema":`, 1))
	if _, err := VerifyJSON(raw, VerifyOptions{}); err == nil {
		t.Fatal("case-aliased envelope property must fail")
	}
}

func TestNewSignerEmptyIsDisabled(t *testing.T) {
	signer, err := NewSigner("")
	if err != nil {
		t.Fatal(err)
	}
	if signer.Enabled() {
		t.Fatal("empty key must not enable signing")
	}
	if _, err := signer.Sign(testPayload(t)); err != ErrDisabled {
		t.Fatalf("expected ErrDisabled, got %v", err)
	}
}

func TestNewSignerRejectsInconsistentExpandedPrivateKey(t *testing.T) {
	seed, err := base64.StdEncoding.DecodeString(testSeedBase64)
	if err != nil {
		t.Fatal(err)
	}
	expanded := ed25519.NewKeyFromSeed(seed)
	expanded[len(expanded)-1] ^= 0xff
	if _, err := NewSigner(base64.RawURLEncoding.EncodeToString(expanded)); err == nil {
		t.Fatal("expanded private key with an inconsistent public half must fail")
	}
}

func TestReceiptActionWindowIsHalfOpen(t *testing.T) {
	signer := testSigner(t)
	payload := testPayload(t)
	envelope, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, _ := time.Parse(TimestampLayout, payload.ExpiresAt)
	verified, err := Verify(envelope, VerifyOptions{Now: expiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Expired {
		t.Fatal("receipt must be expired at the exact expires_at boundary")
	}
}

func TestNegativeClockSkewIsEquivalentToZero(t *testing.T) {
	payload := testPayload(t)
	envelope, err := testSigner(t).Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt, err := time.Parse(TimestampLayout, payload.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err := time.Parse(TimestampLayout, payload.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{issuedAt.Add(time.Second), expiresAt.Add(-time.Second)} {
		withoutSkew, err := Verify(envelope, VerifyOptions{Now: now})
		if err != nil {
			t.Fatal(err)
		}
		negativeSkew, err := Verify(envelope, VerifyOptions{Now: now, ClockSkew: -time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		if negativeSkew.Expired != withoutSkew.Expired || negativeSkew.NotYetValid != withoutSkew.NotYetValid {
			t.Fatalf("negative clock skew must clamp to zero at %s: zero=%+v negative=%+v", now, withoutSkew, negativeSkew)
		}
	}
}

func TestJSONContainerDepthBoundary(t *testing.T) {
	nestedArray := func(depth int) []byte {
		return []byte(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))
	}
	for _, depth := range []int{127, 128} {
		if err := ValidateUniqueJSON(nestedArray(depth)); err != nil {
			t.Fatalf("%d JSON containers must be accepted: %v", depth, err)
		}
	}
	tooDeep := nestedArray(129)
	if err := ValidateUniqueJSON(tooDeep); err == nil || !strings.Contains(err.Error(), "JSON nesting exceeds 128 containers") {
		t.Fatalf("129 JSON containers must return the controlled depth error, got %v", err)
	}
	if _, err := VerifyJSON(tooDeep, VerifyOptions{}); !errors.Is(err, ErrInvalidEnvelope) ||
		!strings.Contains(err.Error(), "JSON nesting exceeds 128 containers") {
		t.Fatalf("VerifyJSON must classify excessive nesting as an invalid envelope, got %v", err)
	}
}

func TestIssuerRequiresCanonicalOrigin(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		issuer string
		valid  bool
	}{
		{name: "canonical_dns", issuer: "https://issuer.example", valid: true},
		{name: "canonical_nondefault_port", issuer: "https://issuer.example:8443", valid: true},
		{name: "canonical_ipv6", issuer: "https://[2001:db8::1]", valid: true},
		{name: "canonical_ipv6_nondefault_port", issuer: "https://[2001:db8::1]:8443", valid: true},
		{name: "uppercase_host", issuer: "https://ISSUER.example", valid: false},
		{name: "default_https_port", issuer: "https://issuer.example:443", valid: false},
		{name: "expanded_ipv6", issuer: "https://[2001:0db8:0:0:0:0:0:1]", valid: false},
		{name: "ipv6_default_https_port", issuer: "https://[2001:db8::1]:443", valid: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := validIssuer(testCase.issuer); got != testCase.valid {
				t.Fatalf("validIssuer(%q) = %t, want %t", testCase.issuer, got, testCase.valid)
			}
			payload := testPayload(t)
			payload.Issuer = testCase.issuer
			_, err := testSigner(t).Sign(payload)
			if testCase.valid && err != nil {
				t.Fatalf("canonical issuer must sign: %v", err)
			}
			if !testCase.valid && !errors.Is(err, ErrInvalidPayload) {
				t.Fatalf("noncanonical issuer must fail as an invalid payload, got %v", err)
			}
		})
	}
}

func TestEvidenceRequiresCanonicalUUIDAndReportLeafBinding(t *testing.T) {
	payload := testPayload(t)
	payload.Evidence = &EvidenceBinding{
		ObservationID: "not-a-uuid", ReportHash: strings.Repeat("42", 32), LeafHash: strings.Repeat("43", 32),
		LogID: strings.Repeat("ab", 16), LogIndex: "0", TreeSize: "1",
		STHRootHash: strings.Repeat("44", 32), STHSHA256Hash: strings.Repeat("45", 32),
	}
	if _, err := testSigner(t).Sign(payload); err == nil {
		t.Fatal("invalid evidence UUID must fail")
	}
	payload.Evidence.ObservationID = "00000000-0000-4000-8000-000000000001"
	if _, err := testSigner(t).Sign(payload); err == nil {
		t.Fatal("mismatched report and RFC6962 leaf hashes must fail")
	}
}

func TestEvidenceAndComputeValidationBoundaries(t *testing.T) {
	signer := testSigner(t)

	t.Run("largest_uint64_values_are_canonical", func(t *testing.T) {
		payload := testPayload(t)
		payload.Evidence = validEvidenceBinding(t)
		payload.Evidence.LogIndex = "18446744073709551614"
		payload.Evidence.TreeSize = "18446744073709551615"
		if _, err := signer.Sign(payload); err != nil {
			t.Fatalf("valid uint64 boundary must sign: %v", err)
		}
	})

	for _, testCase := range []struct {
		name     string
		logIndex string
		treeSize string
	}{
		{name: "leading_zero", logIndex: "05", treeSize: "8"},
		{name: "uint64_overflow", logIndex: "5", treeSize: "18446744073709551616"},
		{name: "index_not_below_tree_size", logIndex: "8", treeSize: "8"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			payload := testPayload(t)
			payload.Evidence = validEvidenceBinding(t)
			payload.Evidence.LogIndex = testCase.logIndex
			payload.Evidence.TreeSize = testCase.treeSize
			if _, err := signer.Sign(payload); !errors.Is(err, ErrInvalidPayload) {
				t.Fatalf("invalid evidence decimal must fail, got %v", err)
			}
		})
	}

	t.Run("compute_artifact_uri_credentials", func(t *testing.T) {
		payload := testPayload(t)
		payload.ComputeProof = &ComputeProof{
			Type:           "zk-proof",
			Provider:       "example-provider",
			ArtifactSHA256: strings.Repeat("77", sha256.Size),
			ArtifactURI:    "https://user:secret@proofs.example/proof.bin",
			Verifier:       "example-adapter/v1",
		}
		if _, err := signer.Sign(payload); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("credential-bearing compute artifact URI must fail, got %v", err)
		}
	})
}

func FuzzVerifyJSONNeverPanics(f *testing.F) {
	signer, err := NewSigner(testSeedBase64)
	if err != nil {
		f.Fatal(err)
	}
	envelope, err := signer.Sign(testPayload(f))
	if err != nil {
		f.Fatal(err)
	}
	valid, err := json.Marshal(envelope)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"schema":"duplicate","schema":"duplicate"}`))
	f.Add([]byte{0xff, 0x00, '{', '}'})

	f.Fuzz(func(t *testing.T, raw []byte) {
		verified, err := VerifyJSON(raw, VerifyOptions{
			Now: time.Date(2026, 9, 1, 3, 6, 0, 0, time.UTC),
		})
		if err == nil && !verified.SignatureValid {
			t.Fatal("successful verification must always report a valid signature")
		}
	})
}
