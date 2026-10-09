package receipt

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// testSeedBase64URL is the public v2 vector seed: bytes 0x40..0x5f.
const testSeedBase64URL = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"

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
	signer, err := NewSigner(testSeedBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func signRawPayload(t *testing.T, signer *Signer, payloadBytes []byte, domain string) Envelope {
	t.Helper()
	payloadHash := sha256.Sum256(payloadBytes)
	message := append([]byte(domain), payloadHash[:]...)
	signature, err := signer.privateKey.Sign(rand.Reader, message, &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return Envelope{
		Schema:        Schema,
		Payload:       base64.RawURLEncoding.EncodeToString(payloadBytes),
		PayloadSHA256: hex.EncodeToString(payloadHash[:]),
		Signature: Signature{
			Algorithm: Algorithm,
			KeyID:     signer.KeyID(),
			PublicKey: signer.PublicKeyBase64URL(),
			Value:     base64.RawURLEncoding.EncodeToString(signature),
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
	nonCanonical := signRawPayload(t, signer, payloadBytes, DomainV2)
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
		`"algorithm":"ML-DSA-65"`,
		`"algorithm":"ML-DSA-65","algorithm":"ML-DSA-65"`,
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

func TestSignedSubjectRequiresInteroperableUTF8JSON(t *testing.T) {
	signer := testSigner(t)
	setSubject := func(payload *Payload, subject []byte) {
		subjectHash := SubjectHash(subject)
		payload.Subject = base64.RawURLEncoding.EncodeToString(subject)
		payload.SubjectSHA256 = hex.EncodeToString(subjectHash[:])
	}

	invalidUTF8 := []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	if !json.Valid(invalidUTF8) {
		t.Fatal("test requires encoding/json's permissive invalid-UTF-8 behavior")
	}
	payload := testPayload(t)
	setSubject(&payload, invalidUTF8)
	if _, err := signer.Sign(payload); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("issuer must reject invalid UTF-8 subject bytes, got %v", err)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signRawPayload(t, signer, payloadBytes, Domain), VerifyOptions{}); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("verifier must reject externally signed invalid UTF-8 subject bytes, got %v", err)
	}

	for name, subject := range map[string][]byte{
		"lone high surrogate": []byte(`{"x":"\ud800"}`),
		"lone low surrogate":  []byte(`{"x":"\udc00"}`),
	} {
		t.Run(name, func(t *testing.T) {
			payload := testPayload(t)
			setSubject(&payload, subject)
			if _, err := signer.Sign(payload); !errors.Is(err, ErrInvalidPayload) {
				t.Fatalf("unpaired JSON surrogate must fail, got %v", err)
			}
		})
	}

	payload = testPayload(t)
	setSubject(&payload, []byte(`{"emoji":"\ud83d\ude00"}`))
	if _, err := signer.Sign(payload); err != nil {
		t.Fatalf("paired JSON surrogate must remain interoperable: %v", err)
	}
}

func TestSubjectMatchesJSONRejectsUnicodeDecoderReplacement(t *testing.T) {
	subject := []byte(`{"x":"\ufffd"}`)
	payload := testPayload(t)
	subjectHash := SubjectHash(subject)
	payload.Subject = base64.RawURLEncoding.EncodeToString(subject)
	payload.SubjectSHA256 = hex.EncodeToString(subjectHash[:])
	envelope, err := testSigner(t).Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := Verify(envelope, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}

	loneSurrogate := []byte(`{"x":"\ud800"}`)
	if err := ValidateUniqueJSON(loneSurrogate); err == nil {
		t.Fatal("shared strict JSON validation must reject an unpaired surrogate")
	}
	if verification.SubjectMatchesJSON(loneSurrogate) {
		t.Fatal("outer binding must not equate an unpaired surrogate with the replacement character")
	}
	invalidUTF8 := []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	if err := ValidateUniqueJSON(invalidUTF8); err == nil {
		t.Fatal("shared strict JSON validation must reject invalid UTF-8")
	}
	if verification.SubjectMatchesJSON(invalidUTF8) {
		t.Fatal("outer binding must reject invalid UTF-8")
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

func TestNewSignerRequiresCanonicalSeedAndNeverEchoesIt(t *testing.T) {
	good := testSeedBase64URL
	cases := map[string]string{
		"padded":          good + "=",
		"std alphabet":    good[:10] + "+" + good[11:],
		"short":           good[:42],
		"long":            good + "A",
		"noncanonical":    good[:42] + "F", // final sextet carries non-zero unused bits
		"ed25519 private": base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		"whitespace":      " " + good,
		"not base64":      strings.Repeat("!", 43),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewSigner(value)
			if err == nil {
				t.Fatal("seed must be rejected")
			}
			if strings.Contains(err.Error(), value) || strings.Contains(err.Error(), good) {
				t.Fatal("error must never contain the seed value")
			}
		})
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

func TestReceiptActionWindowPreservesMicroseconds(t *testing.T) {
	payload := testPayload(t)
	payload.IssuedAt = "2026-09-01T03:04:05.000999Z"
	payload.ExpiresAt = "2026-09-01T03:09:05.001999Z"
	envelope, err := testSigner(t).Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		name            string
		now             string
		wantNotYetValid bool
		wantExpired     bool
	}{
		{name: "before issue in same millisecond", now: "2026-09-01T03:04:05.000500Z", wantNotYetValid: true},
		{name: "exact issue microsecond", now: payload.IssuedAt},
		{name: "before expiry in same millisecond", now: "2026-09-01T03:09:05.001500Z"},
		{name: "exact expiry microsecond", now: payload.ExpiresAt, wantExpired: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			now, parseErr := time.Parse(TimestampLayout, testCase.now)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			verification, verifyErr := Verify(envelope, VerifyOptions{Now: now})
			if verifyErr != nil {
				t.Fatal(verifyErr)
			}
			if verification.NotYetValid != testCase.wantNotYetValid || verification.Expired != testCase.wantExpired {
				t.Fatalf("microsecond time state = notYet:%t expired:%t, want notYet:%t expired:%t",
					verification.NotYetValid, verification.Expired, testCase.wantNotYetValid, testCase.wantExpired)
			}
		})
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
		{name: "canonical_zero_port", issuer: "https://issuer.example:0", valid: true},
		{name: "canonical_max_port", issuer: "https://issuer.example:65535", valid: true},
		{name: "hexadecimal_dns_labels", issuer: "https://dead.beef", valid: true},
		{name: "punycode_dns_label", issuer: "https://xn--bcher-kva.example", valid: true},
		{name: "loopback_localhost", issuer: "http://localhost:8080", valid: true},
		{name: "loopback_127_8", issuer: "http://127.0.0.2", valid: true},
		{name: "loopback_127_8_nondefault_port", issuer: "http://127.255.255.255:8080", valid: true},
		{name: "loopback_ipv6", issuer: "http://[::1]", valid: true},
		{name: "uppercase_host", issuer: "https://ISSUER.example", valid: false},
		{name: "default_https_port", issuer: "https://issuer.example:443", valid: false},
		{name: "expanded_ipv6", issuer: "https://[2001:0db8:0:0:0:0:0:1]", valid: false},
		{name: "ipv6_default_https_port", issuer: "https://[2001:db8::1]:443", valid: false},
		{name: "ipv4_mapped_ipv6", issuer: "https://[::ffff:c000:280]", valid: false},
		{name: "ipv4_mapped_ipv6_nondefault_port", issuer: "https://[::ffff:7f00:1]:8443", valid: false},
		{name: "short_ipv4", issuer: "https://127.1", valid: false},
		{name: "integer_ipv4", issuer: "https://2130706433", valid: false},
		{name: "hex_ipv4", issuer: "https://0x7f000001", valid: false},
		{name: "empty_hex_ipv4", issuer: "https://0x", valid: false},
		{name: "empty_hex_numeric_tld", issuer: "https://example.0x", valid: false},
		{name: "octal_ipv4", issuer: "https://0177.0.0.1", valid: false},
		{name: "numeric_tld", issuer: "https://example.1", valid: false},
		{name: "stray_close_bracket", issuer: "https://a]b.example", valid: false},
		{name: "stray_open_bracket", issuer: "https://a[b.example", valid: false},
		{name: "backtick_host", issuer: "https://a`b.example", valid: false},
		{name: "open_brace_host", issuer: "https://a{b.example", valid: false},
		{name: "close_brace_host", issuer: "https://a}b.example", valid: false},
		{name: "underscore_host", issuer: "https://a_b.example", valid: false},
		{name: "leading_hyphen_label", issuer: "https://-a.example", valid: false},
		{name: "trailing_hyphen_label", issuer: "https://a-.example", valid: false},
		{name: "trailing_dot", issuer: "https://issuer.example.", valid: false},
		{name: "leading_zero_port", issuer: "https://issuer.example:08443", valid: false},
		{name: "padded_zero_port", issuer: "https://issuer.example:00000", valid: false},
		{name: "port_out_of_range", issuer: "https://issuer.example:65536", valid: false},
		{name: "nonloopback_http_dns", issuer: "http://issuer.example", valid: false},
		{name: "nonloopback_http_ip", issuer: "http://192.0.2.1", valid: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			issuerErr := ValidateIssuer(testCase.issuer)
			if got := issuerErr == nil; got != testCase.valid {
				t.Fatalf("ValidateIssuer(%q) valid = %t, want %t (error: %v)", testCase.issuer, got, testCase.valid, issuerErr)
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

func TestNormalizeIssuerMatchesNewPayloadInputSemantics(t *testing.T) {
	for name, testCase := range map[string]struct {
		input string
		want  string
	}{
		"canonical":              {input: "https://issuer.example", want: "https://issuer.example"},
		"trailing slash":         {input: "https://issuer.example/", want: "https://issuer.example"},
		"surrounding whitespace": {input: "  https://issuer.example/  ", want: "https://issuer.example"},
		"nondefault port":        {input: "https://issuer.example:8443/", want: "https://issuer.example:8443"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := NormalizeIssuer(testCase.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != testCase.want {
				t.Fatalf("NormalizeIssuer(%q) = %q, want %q", testCase.input, got, testCase.want)
			}
		})
	}

	for _, input := range []string{
		"https://ISSUER.example",
		"https://issuer.example:443",
		"https://[2001:0db8:0:0:0:0:0:1]",
	} {
		if _, err := NormalizeIssuer(input); err == nil {
			t.Fatalf("NormalizeIssuer(%q) must reject noncanonical input", input)
		}
	}

	now := time.Date(2026, 9, 1, 3, 4, 5, 0, time.UTC)
	payload, err := NewPayload(
		"https://issuer.example/", "service", now, now.Add(time.Minute), nil,
		[]byte(`{"request":true}`), []byte(`{"response":true}`), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Issuer != "https://issuer.example" {
		t.Fatalf("NewPayload issuer = %q, want normalized origin", payload.Issuer)
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
	signer, err := NewSigner(testSeedBase64URL)
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
