package receipt

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	vectorV2Path     = "../../spec/testdata/service_receipt_v2.json"
	vectorV2Warning  = "This key is intentionally public. Never trust a receipt because it uses this key."
	vectorCurrentTim = "2026-09-01T03:06:00.000000Z"
)

type v2Expected struct {
	SignatureValid     bool   `json:"signature_valid"`
	IssuerTrusted      bool   `json:"issuer_trusted"`
	Expired            bool   `json:"expired"`
	NotYetValid        bool   `json:"not_yet_valid"`
	EvidenceStatus     string `json:"evidence_status"`
	ComputeProofStatus string `json:"compute_proof_status"`
}

type v2Policy struct {
	ExpectedIssuer string   `json:"expected_issuer"`
	TrustedKeyIDs  []string `json:"trusted_key_ids"`
}

type v2Case struct {
	Description   string     `json:"description,omitempty"`
	Request       string     `json:"canonical_request,omitempty"`
	Subject       string     `json:"canonical_subject,omitempty"`
	Payload       string     `json:"canonical_payload"`
	PayloadSHA256 string     `json:"payload_sha256"`
	SigningDigest string     `json:"signing_digest_sha256"`
	SignedMessage string     `json:"signed_message_hex"`
	KeyID         string     `json:"key_id"`
	PublicKey     string     `json:"public_key_base64url"`
	Signature     string     `json:"signature_base64url"`
	Envelope      Envelope   `json:"envelope"`
	Policy        v2Policy   `json:"trusted_policy"`
	CurrentTime   string     `json:"current_time"`
	Expected      v2Expected `json:"expected"`
}

type v2DirectoryEntry struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Status    string `json:"status"`
}

type v2Negative struct {
	Name          string             `json:"name"`
	Mutation      string             `json:"mutation"`
	ExpectedError string             `json:"expected_error,omitempty"`
	Expected      map[string]bool    `json:"expected,omitempty"`
	Envelope      *Envelope          `json:"envelope,omitempty"`
	ExpectedIssue string             `json:"expected_issuer,omitempty"`
	CurrentTime   string             `json:"current_time,omitempty"`
	Directory     []v2DirectoryEntry `json:"directory,omitempty"`
}

type v2File struct {
	Description    string            `json:"description"`
	Seed           string            `json:"test_private_key_seed_base64url"`
	SeedWarning    string            `json:"test_private_key_seed_warning"`
	Signing        string            `json:"signing"`
	Domains        map[string]string `json:"domains"`
	Request        string            `json:"canonical_request"`
	Subject        string            `json:"canonical_subject"`
	Valid          v2Case            `json:"valid"`
	EvidenceCompte v2Case            `json:"evidence_compute"`
	Negative       []v2Negative      `json:"negative_cases"`
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrInvalidSignature):
		return "invalid_signature"
	case errors.Is(err, ErrUnsupportedSchema):
		return "unsupported_schema"
	case errors.Is(err, ErrInvalidPayload):
		return "invalid_payload"
	case errors.Is(err, ErrInvalidEnvelope):
		return "invalid_envelope"
	}
	return "other"
}

func b64u(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func buildV2Case(t *testing.T, signer *Signer, v1 publishedCase, request, subject string) v2Case {
	t.Helper()
	var payload Payload
	if err := json.Unmarshal([]byte(v1.CanonicalPayload), &payload); err != nil {
		t.Fatal(err)
	}
	payload.Schema = SchemaV2
	envelope, err := signer.sign(payload, true)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, _ := json.Marshal(payload)
	digest := sha256.Sum256(payloadBytes)
	verified, err := Verify(envelope, VerifyOptions{
		TrustedKeyIDs: []string{signer.KeyID()}, ExpectedIssuer: "https://ifandonlyif.io", Now: mustTime(t, vectorCurrentTim),
	})
	if err != nil {
		t.Fatal(err)
	}
	return v2Case{
		Request: request, Subject: subject,
		Payload: string(payloadBytes), PayloadSHA256: hex.EncodeToString(digest[:]),
		SigningDigest: hex.EncodeToString(digest[:]), SignedMessage: hex.EncodeToString(signingMessageV2(payloadBytes)),
		KeyID: signer.KeyID(), PublicKey: signer.PublicKeyBase64URL(), Signature: envelope.Signature.Value,
		Envelope: envelope, Policy: v2Policy{ExpectedIssuer: "https://ifandonlyif.io", TrustedKeyIDs: []string{signer.KeyID()}},
		CurrentTime: vectorCurrentTim,
		Expected: v2Expected{
			SignatureValid: verified.SignatureValid, IssuerTrusted: verified.IssuerTrusted, Expired: verified.Expired,
			NotYetValid: verified.NotYetValid, EvidenceStatus: verified.EvidenceStatus, ComputeProofStatus: verified.ComputeProofStatus,
		},
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(TimestampLayout, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func buildV2Vectors(t *testing.T) v2File {
	t.Helper()
	v1 := loadPublishedVector(t)
	signer := testSigner(t)
	valid := buildV2Case(t, signer, v1.Valid, v1.CanonicalRequest, v1.CanonicalSubject)
	compute := buildV2Case(t, signer, v1.EvidenceCompute, v1.EvidenceCompute.CanonicalRequest, v1.EvidenceCompute.CanonicalSubject)
	compute.Description = "Evidence/compute descriptor vector bound to transparency-log test leaf 5. Base verification binds the descriptor bytes only; it does not verify the referenced evidence or compute proof."
	compute.Request, compute.Subject = v1.EvidenceCompute.CanonicalRequest, v1.EvidenceCompute.CanonicalSubject

	payloadBytes := []byte(valid.Payload)
	base := valid.Envelope
	mutateSig := func(edit func(raw []byte) []byte) Envelope {
		raw, _ := base64.RawURLEncoding.DecodeString(base.Signature.Value)
		out := base
		out.Signature.Value = b64u(edit(raw))
		return out
	}
	privateKey := signer.privateKey
	signRaw := func(message []byte) string {
		sig, err := privateKey.SignDeterministic(message, &mldsa.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return b64u(sig)
	}
	digest := sha256.Sum256(payloadBytes)
	v1Digest := signingDigest(payloadBytes)

	negatives := []v2Negative{}
	add := func(n v2Negative) { negatives = append(negatives, n) }

	tampered := base
	tamperedPayload := strings.Replace(valid.Payload, "checkout_7f3a", "checkout_7f3b", 1)
	tampered.Payload = b64u([]byte(tamperedPayload))
	add(v2Negative{Name: "tampered_payload", Mutation: "replace checkout_7f3a with checkout_7f3b in canonical_payload without changing payload_sha256 or signature", ExpectedError: "invalid_envelope", Envelope: &tampered})

	flipped := mutateSig(func(raw []byte) []byte { raw[0] ^= 0xff; return raw })
	add(v2Negative{Name: "tampered_signature", Mutation: "flip the first decoded signature byte", ExpectedError: "invalid_signature", Envelope: &flipped})

	add(v2Negative{Name: "wrong_expected_issuer", Mutation: "verify the valid envelope with expected issuer https://other.example", ExpectedIssue: "https://other.example", Expected: map[string]bool{"signature_valid": true, "issuer_trusted": false}})
	add(v2Negative{Name: "expires_at_boundary", Mutation: "verify the valid envelope at 2026-09-01T03:09:05.000000Z", CurrentTime: "2026-09-01T03:09:05.000000Z", Expected: map[string]bool{"signature_valid": true, "expired": true}})

	key := base
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, key.Signature.PublicKey[len(key.Signature.PublicKey)-1])
	key.Signature.PublicKey = key.Signature.PublicKey[:len(key.Signature.PublicKey)-1] + string(alphabet[(last&^3)+1])
	add(v2Negative{Name: "noncanonical_public_key_base64url", Mutation: "change the final public-key character so the unused trailing bits are non-zero (1952 bytes leave two unused bits)", ExpectedError: "invalid_envelope", Envelope: &key})

	v1Schema := base
	v1Schema.Schema = SchemaV1
	add(v2Negative{Name: "v1_schema_with_mldsa_signature", Mutation: "set the envelope schema to the v1 schema and keep the ML-DSA-65 algorithm, key and signature", ExpectedError: "invalid_envelope", Envelope: &v1Schema})

	edAlgorithm := base
	edAlgorithm.Signature.Algorithm = AlgorithmEd25519
	add(v2Negative{Name: "v2_schema_with_ed25519_algorithm", Mutation: "set signature.algorithm to Ed25519 on the v2 envelope", ExpectedError: "invalid_envelope", Envelope: &edAlgorithm})

	edPriv := ed25519.NewKeyFromSeed([]byte("iff-service-receipt-v2-vector-ed"))
	edPub := edPriv.Public().(ed25519.PublicKey)
	edSig := ed25519.Sign(edPriv, v1Digest[:])
	edKeys := base
	edKeys.Signature = Signature{Algorithm: AlgorithmMLDSA65, KeyID: KeyID(edPub), PublicKey: b64u(edPub), Value: b64u(edSig)}
	add(v2Negative{Name: "v2_schema_with_ed25519_key_and_signature", Mutation: "v2 envelope whose public_key is a 32-byte Ed25519 key and whose value is a 64-byte Ed25519 signature, key_id derived from that key", ExpectedError: "invalid_envelope", Envelope: &edKeys})

	v1Signed := base
	v1Signed.Signature.Value = signRaw(v1Digest[:])
	add(v2Negative{Name: "v1_signing_digest_signed_with_mldsa", Mutation: "ML-DSA-65 signature over the 32-byte v1 digest SHA-256(\"iff-service-receipt/v1\\n\" || payload)", ExpectedError: "invalid_signature", Envelope: &v1Signed})

	domainless := base
	domainless.Signature.Value = signRaw(digest[:])
	add(v2Negative{Name: "domainless_digest_signed_with_mldsa", Mutation: "ML-DSA-65 signature over SHA-256(payload) without the domain line", ExpectedError: "invalid_signature", Envelope: &domainless})

	wrongDomain := base
	wrongDomain.Signature.Value = signRaw(append([]byte("another-protocol/v2\n"), digest[:]...))
	add(v2Negative{Name: "wrong_domain_line", Mutation: "ML-DSA-65 signature over \"another-protocol/v2\\n\" || SHA-256(payload)", ExpectedError: "invalid_signature", Envelope: &wrongDomain})

	rawKey, _ := base64.RawURLEncoding.DecodeString(base.Signature.PublicKey)
	shortKey := base
	shortKey.Signature.PublicKey = b64u(rawKey[:len(rawKey)-1])
	shortKey.Signature.KeyID = KeyID(rawKey[:len(rawKey)-1])
	add(v2Negative{Name: "public_key_one_byte_short", Mutation: "drop the last public-key byte (1951 bytes) and derive key_id from the short key", ExpectedError: "invalid_envelope", Envelope: &shortKey})

	shortSig := mutateSig(func(raw []byte) []byte { return raw[:len(raw)-1] })
	add(v2Negative{Name: "signature_one_byte_short", Mutation: "drop the last signature byte (3308 bytes)", ExpectedError: "invalid_envelope", Envelope: &shortSig})

	var mismatched Payload
	if err := json.Unmarshal(payloadBytes, &mismatched); err != nil {
		t.Fatal(err)
	}
	mismatched.Schema = SchemaV1
	mismatchedBytes, _ := json.Marshal(mismatched)
	mismatchedHash := sha256.Sum256(mismatchedBytes)
	payloadMismatch := Envelope{
		Schema: SchemaV2, Payload: b64u(mismatchedBytes), PayloadSHA256: hex.EncodeToString(mismatchedHash[:]),
		Signature: Signature{Algorithm: AlgorithmMLDSA65, KeyID: signer.KeyID(), PublicKey: signer.PublicKeyBase64URL(), Value: signRaw(signingMessageV2(mismatchedBytes))},
	}
	add(v2Negative{Name: "payload_schema_differs_from_envelope_schema", Mutation: "validly sign a payload whose schema is the v1 schema inside a v2 envelope", ExpectedError: "unsupported_schema", Envelope: &payloadMismatch})

	add(v2Negative{
		Name:     "directory_entry_algorithm_mismatch",
		Mutation: "a directory entry with the receipt's key_id and public_key but algorithm Ed25519 must not recognize the receipt",
		Expected: map[string]bool{"recognized": false},
		Envelope: &base,
		Directory: []v2DirectoryEntry{{
			KeyID: base.Signature.KeyID, Algorithm: AlgorithmEd25519, PublicKey: base.Signature.PublicKey, Status: "current",
		}},
	})

	return v2File{
		Description: "Known-answer material for IFF Service Receipt v2 (ML-DSA-65). Construct envelope.payload as unpadded base64url of canonical_payload. " +
			"The signed message is \"iff-service-receipt/v2\\n\" || SHA-256(canonical_payload); signing_digest_sha256 is that SHA-256 and equals payload_sha256. " +
			"Payloads are the v1 vector payloads with the v2 schema. Negative cases give the envelope to verify and the stable error code a verifier must report.",
		Seed:        b64u(seedBytes(0x40)),
		SeedWarning: vectorV2Warning,
		Signing:     "deterministic (FIPS 204 rnd = 32 zero bytes); production signatures are hedged",
		Domains: map[string]string{
			"signature":    DomainV2,
			"request_hash": requestHashDomain,
			"subject_hash": subjectHashDomain,
		},
		Request: v1.CanonicalRequest, Subject: v1.CanonicalSubject,
		Valid: valid, EvidenceCompte: compute, Negative: negatives,
	}
}

func seedBytes(start byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

// TestPublishedServiceReceiptV2Vectors asserts the freshly built vectors are
// byte-for-byte identical to spec/testdata/service_receipt_v2.json; it also verifies every
// case independently of how it was built.
func TestPublishedServiceReceiptV2Vectors(t *testing.T) {
	fresh := buildV2Vectors(t)
	if fresh.Seed != testSeedBase64URL {
		t.Fatal("test seed must be bytes 0x40..0x5f")
	}
	freshJSON, err := json.MarshalIndent(fresh, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	freshJSON = append(freshJSON, '\n')
	existing, err := os.ReadFile(vectorV2Path)
	if err != nil {
		// The checked-in file comes from the reference implementation and is
		// never regenerated here.
		t.Fatal(err)
	}
	if string(existing) != string(freshJSON) {
		t.Fatalf("%s differs from the vectors rebuilt by this test", vectorV2Path)
	}

	var published v2File
	if err := json.Unmarshal(existing, &published); err != nil {
		t.Fatal(err)
	}
	for name, testCase := range map[string]v2Case{"valid": published.Valid, "evidence_compute": published.EvidenceCompte} {
		t.Run(name, func(t *testing.T) {
			envelopeJSON, _ := json.Marshal(testCase.Envelope)
			verified, err := VerifyJSON(envelopeJSON, VerifyOptions{
				TrustedKeyIDs: testCase.Policy.TrustedKeyIDs, ExpectedIssuer: testCase.Policy.ExpectedIssuer, Now: mustTime(t, testCase.CurrentTime),
			})
			if err != nil {
				t.Fatal(err)
			}
			if verified.Algorithm != AlgorithmMLDSA65 || verified.SignatureValid != testCase.Expected.SignatureValid ||
				verified.IssuerTrusted != testCase.Expected.IssuerTrusted || verified.EvidenceStatus != testCase.Expected.EvidenceStatus ||
				verified.ComputeProofStatus != testCase.Expected.ComputeProofStatus || verified.Expired != testCase.Expected.Expired {
				t.Fatalf("unexpected result %+v", verified)
			}
			if string(verified.Subject) != testCase.Subject {
				t.Fatal("subject vector drifted")
			}
			if hex.EncodeToString(signingMessageV2([]byte(testCase.Payload))) != testCase.SignedMessage {
				t.Fatal("signed message drifted")
			}
		})
	}
	assertEvidenceMatchesTransparencyVector(t, published.EvidenceCompte.Envelope)

	for _, negative := range published.Negative {
		t.Run(negative.Name, func(t *testing.T) {
			if len(negative.Directory) > 0 {
				for _, entry := range negative.Directory {
					recognized := entry.KeyID == negative.Envelope.Signature.KeyID && entry.Algorithm == negative.Envelope.Signature.Algorithm &&
						entry.PublicKey == negative.Envelope.Signature.PublicKey
					if recognized != negative.Expected["recognized"] {
						t.Fatal("directory recognition disagrees with the vector")
					}
				}
				return
			}
			envelope := published.Valid.Envelope
			if negative.Envelope != nil {
				envelope = *negative.Envelope
			}
			issuer := published.Valid.Policy.ExpectedIssuer
			if negative.ExpectedIssue != "" {
				issuer = negative.ExpectedIssue
			}
			now := published.Valid.CurrentTime
			if negative.CurrentTime != "" {
				now = negative.CurrentTime
			}
			verified, err := Verify(envelope, VerifyOptions{TrustedKeyIDs: published.Valid.Policy.TrustedKeyIDs, ExpectedIssuer: issuer, Now: mustTime(t, now)})
			if negative.ExpectedError != "" {
				if err == nil || errorCode(err) != negative.ExpectedError {
					t.Fatalf("want %s, got %v", negative.ExpectedError, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if verified.SignatureValid != negative.Expected["signature_valid"] ||
				verified.IssuerTrusted != published.Valid.Expected.IssuerTrusted && negative.Expected["issuer_trusted"] ||
				verified.Expired != negative.Expected["expired"] {
				t.Fatalf("unexpected result %+v", verified)
			}
			if negative.Name == "wrong_expected_issuer" && verified.IssuerTrusted {
				t.Fatal("issuer must not be trusted")
			}
		})
	}
}
