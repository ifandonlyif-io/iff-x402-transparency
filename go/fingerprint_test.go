package preflight

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// fingerprintVectorFile mirrors spec/testdata/fingerprint_vectors.json,
// the public cross-language contract (C1 + C4 rule 4b).
type fingerprintVectorFile struct {
	Vectors []fingerprintVector `json:"vectors"`
}

type fingerprintVector struct {
	Name                string          `json:"name"`
	Options             []PaymentOption `json:"options"`
	OK                  bool            `json:"ok"`
	SetFingerprint      string          `json:"set_fingerprint"`
	OptionFingerprints  []string        `json:"option_fingerprints"`
	FingerprintVersion  int             `json:"fingerprint_version"`
	PayeeFingerprints   []string        `json:"payee_fingerprints"`
	PayeeSetFingerprint string          `json:"payee_set_fingerprint"`
}

// findVectorsFile resolves the public vectors relative to this source file,
// so the test is independent of the caller's working directory.
func findVectorsFile(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate fingerprint_test.go")
	}
	return filepath.Join(filepath.Dir(sourceFile), "..", "spec", "testdata", "fingerprint_vectors.json")
}

// loadFingerprintVectors locates and parses the vectors file.
func loadFingerprintVectors(t *testing.T) fingerprintVectorFile {
	t.Helper()
	path := findVectorsFile(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc fingerprintVectorFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	if len(doc.Vectors) < 8 {
		t.Fatalf("C1 requires at least 8 cross-language fingerprint vectors, got %d", len(doc.Vectors))
	}
	return doc
}

func TestComputeFingerprintVectors(t *testing.T) {
	doc := loadFingerprintVectors(t)
	for _, vector := range doc.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			fp, ok := ComputeFingerprint(vector.Options)
			if ok != vector.OK {
				t.Fatalf("ok mismatch: got %v want %v", ok, vector.OK)
			}
			if !vector.OK {
				if !reflect.DeepEqual(fp, Fingerprint{}) {
					t.Fatalf("expected zero Fingerprint for ok=false, got %+v", fp)
				}
				return
			}
			if fp.SetFP != vector.SetFingerprint {
				t.Errorf("set_fingerprint mismatch: got %s want %s", fp.SetFP, vector.SetFingerprint)
			}
			if !reflect.DeepEqual(fp.OptionFPs, vector.OptionFingerprints) {
				t.Errorf("option_fingerprints mismatch: got %v want %v", fp.OptionFPs, vector.OptionFingerprints)
			}
			if len(fp.SetFP) != 64 {
				t.Errorf("set_fingerprint length = %d, want 64", len(fp.SetFP))
			}
		})
	}
}

func TestComputePayeeFingerprintVectors(t *testing.T) {
	doc := loadFingerprintVectors(t)
	for _, vector := range doc.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			payeeFP, ok := ComputePayeeFingerprint(vector.Options)
			if ok != vector.OK {
				t.Fatalf("ok mismatch: got %v want %v", ok, vector.OK)
			}
			if !vector.OK {
				if !reflect.DeepEqual(payeeFP, PayeeFingerprint{}) {
					t.Fatalf("expected zero PayeeFingerprint for ok=false, got %+v", payeeFP)
				}
				return
			}
			if payeeFP.PayeeSetFP != vector.PayeeSetFingerprint {
				t.Errorf("payee_set_fingerprint mismatch: got %s want %s", payeeFP.PayeeSetFP, vector.PayeeSetFingerprint)
			}
			if !reflect.DeepEqual(payeeFP.PayeeFPs, vector.PayeeFingerprints) {
				t.Errorf("payee_fingerprints mismatch: got %v want %v", payeeFP.PayeeFPs, vector.PayeeFingerprints)
			}
		})
	}
}

func findVector(t *testing.T, doc fingerprintVectorFile, name string) fingerprintVector {
	t.Helper()
	for _, v := range doc.Vectors {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("vector %q not found", name)
	return fingerprintVector{}
}

func TestPayeeFingerprintSharedAcrossAmount(t *testing.T) {
	doc := loadFingerprintVectors(t)
	basic := findVector(t, doc, "single_option_basic")
	amountA := findVector(t, doc, "payee_fingerprint_shared_across_amount_a")
	amountB := findVector(t, doc, "payee_fingerprint_shared_across_amount_b")

	if basic.SetFingerprint == amountA.SetFingerprint {
		t.Error("amount differs, so the ordinary set_fingerprint must differ")
	}
	if basic.PayeeSetFingerprint != amountA.PayeeSetFingerprint {
		t.Error("payee fingerprint excludes amount, so it must match")
	}
	if basic.PayeeSetFingerprint != amountB.PayeeSetFingerprint {
		t.Error("payee fingerprint excludes amount, so it must match")
	}
}

func TestComputeFingerprintEmptySet(t *testing.T) {
	if fp, ok := ComputeFingerprint(nil); ok || !reflect.DeepEqual(fp, Fingerprint{}) {
		t.Errorf("expected ok=false and zero value for nil options, got %v %+v", ok, fp)
	}
	if fp, ok := ComputePayeeFingerprint(nil); ok || !reflect.DeepEqual(fp, PayeeFingerprint{}) {
		t.Errorf("expected ok=false and zero value for nil options, got %v %+v", ok, fp)
	}
}

// TestManualSHA256Verification independently checks the single_option_basic
// vector using only canonical serialization and SHA-256.
func TestManualSHA256Verification(t *testing.T) {
	option := PaymentOption{
		Scheme: "exact", Network: "eip155:8453",
		Asset:  "0xab12cd34ab12cd34ab12cd34ab12cd34ab12cd34",
		PayTo:  "0xef56ab78ef56ab78ef56ab78ef56ab78ef56ab78",
		Amount: "1000000", MaxTimeoutSeconds: 60,
	}
	fp, ok := ComputeFingerprint([]PaymentOption{option})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if fp.OptionFPs[0] != "368387837e4883346a4479ec48d19718b432b70f7185c77b4a2150a07d61c768" {
		t.Errorf("option fingerprint = %s", fp.OptionFPs[0])
	}
	if fp.SetFP != "91639af6f1dc968c3506c117712fc7830368e7cad3e2dd7cebe209cbb4f229ea" {
		t.Errorf("set fingerprint = %s", fp.SetFP)
	}
}

func TestCanonicalPaymentOptionFieldOrder(t *testing.T) {
	payload := marshalCanonicalJSON(canonicalPaymentOption{
		Scheme: "exact", Network: "eip155:8453", Asset: "0xasset", PayTo: "0xpayto", Amount: "1",
	})
	want := `{"scheme":"exact","network":"eip155:8453","asset":"0xasset","pay_to":"0xpayto","amount":"1"}`
	if string(payload) != want {
		t.Fatalf("canonical payload = %s, want %s", payload, want)
	}
}

func TestMarshalCanonicalJSONDoesNotEscapeHTML(t *testing.T) {
	payload := marshalCanonicalJSON(canonicalPaymentOption{
		Scheme: "exact", Network: "eip155:8453", Asset: "<script>", PayTo: "a&b", Amount: "1",
	})
	encoded := string(payload)
	for _, raw := range []string{"<script>", "a&b"} {
		if !strings.Contains(encoded, raw) {
			t.Errorf("canonical payload %q does not contain %q", encoded, raw)
		}
	}
	for _, escaped := range []string{"\\u003c", "\\u003e", "\\u0026"} {
		if strings.Contains(encoded, escaped) {
			t.Errorf("canonical payload %q contains escaped value %q", encoded, escaped)
		}
	}
}
