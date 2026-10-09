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

func TestParsePublicKeySelectsAlgorithmByLength(t *testing.T) {
	signer := testSigner(t)
	mlKey, err := ParsePublicKey(signer.PublicKeyBase64URL())
	if err != nil || mlKey.Algorithm != AlgorithmMLDSA65 || mlKey.KeyID != signer.KeyID() {
		t.Fatalf("ML-DSA-65 key: %+v, %v", mlKey, err)
	}
	edKey, err := ParsePublicKey(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if err != nil || edKey.Algorithm != AlgorithmEd25519 {
		t.Fatalf("Ed25519 key: %+v, %v", edKey, err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(signer.PublicKeyBase64URL())
	for _, length := range []int{0, 31, 33, 64, 1951, 1953} {
		candidate := make([]byte, length)
		copy(candidate, raw)
		if _, err := ParsePublicKey(base64.RawURLEncoding.EncodeToString(candidate)); err == nil {
			t.Fatalf("length %d must be rejected", length)
		}
	}
}

// v1Envelope builds a historical Ed25519 receipt the way the old signer did.
func v1Envelope(t *testing.T) Envelope {
	t.Helper()
	payload := testPayload(t)
	payload.Schema = SchemaV1
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := private.Public().(ed25519.PublicKey)
	digest := signingDigest(payloadBytes)
	hash := sha256.Sum256(payloadBytes)
	return Envelope{
		Schema: SchemaV1, Payload: base64.RawURLEncoding.EncodeToString(payloadBytes), PayloadSHA256: hex.EncodeToString(hash[:]),
		Signature: Signature{Algorithm: AlgorithmEd25519, KeyID: KeyID(public), PublicKey: base64.RawURLEncoding.EncodeToString(public),
			Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, digest[:]))},
	}
}

func TestV1AndV2VerifyAndNeverCrossMix(t *testing.T) {
	now := VerifyOptions{Now: time.Date(2026, 9, 1, 3, 6, 0, 0, time.UTC)}
	v1 := v1Envelope(t)
	verified, err := Verify(v1, now)
	if err != nil || verified.Algorithm != AlgorithmEd25519 {
		t.Fatalf("v1: %+v, %v", verified, err)
	}
	signer := testSigner(t)
	v2, err := signer.Sign(testPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	verified, err = Verify(v2, now)
	if err != nil || verified.Algorithm != AlgorithmMLDSA65 || verified.Payload.Schema != SchemaV2 {
		t.Fatalf("v2: %+v, %v", verified, err)
	}

	// The signer refuses to issue v1.
	v1Payload := testPayload(t)
	v1Payload.Schema = SchemaV1
	if _, err := signer.Sign(v1Payload); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("v1 issuance must be refused, got %v", err)
	}

	cases := map[string]func(Envelope) Envelope{
		"v1 schema with ML-DSA-65 envelope": func(e Envelope) Envelope { e.Schema = SchemaV1; return e },
		"v2 schema with Ed25519 algorithm":  func(e Envelope) Envelope { e.Signature.Algorithm = AlgorithmEd25519; return e },
	}
	for name, edit := range cases {
		if _, err := Verify(edit(v2), now); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	mixedV1 := v1
	mixedV1.Schema = SchemaV2
	if _, err := Verify(mixedV1, now); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("v2 schema with an Ed25519 key and signature: got %v", err)
	}
	mixedV1 = v1
	mixedV1.Signature.Algorithm = AlgorithmMLDSA65
	if _, err := Verify(mixedV1, now); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("v1 schema with ML-DSA-65 algorithm: got %v", err)
	}
	if _, err := Verify(Envelope{Schema: strings.Replace(SchemaV2, "v2", "v3", 1)}, now); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("unknown schema: got %v", err)
	}
}
