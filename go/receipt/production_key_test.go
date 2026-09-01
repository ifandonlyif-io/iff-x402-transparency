package receipt

import (
	"os"
	"testing"
)

func TestPublishedProductionReceiptKeyPin(t *testing.T) {
	const (
		expectedKeyID     = "sha256:0f872f79cd935ac2d764589c8283d35ae0ca02780faebee8862db85348fc5ceb"
		expectedPublicKey = "iVnUmYYy_PO_M3wFYWwc91wxVPU6VRyEcPr9iC4F230"
	)

	type keyEntry struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
		Purpose   string `json:"purpose"`
		Status    string `json:"status"`
	}
	var directory struct {
		Schema  string     `json:"schema"`
		Issuer  string     `json:"issuer"`
		Enabled bool       `json:"enabled"`
		Keys    []keyEntry `json:"keys"`
	}

	raw, err := os.ReadFile("../../keys/service-receipt-production-2026-09-01.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateUniqueJSON(raw); err != nil {
		t.Fatal(err)
	}
	if err := decodeStrict(raw, &directory); err != nil {
		t.Fatal(err)
	}
	if directory.Schema != "https://ifandonlyif.io/schemas/service-receipt-key-directory-v1.json" ||
		directory.Issuer != "https://ifandonlyif.io" || !directory.Enabled || len(directory.Keys) != 1 {
		t.Fatalf("unexpected production receipt-key directory: %+v", directory)
	}
	entry := directory.Keys[0]
	if entry.Algorithm != Algorithm || entry.Purpose != "service-receipt-signing" || entry.Status != "current" {
		t.Fatalf("unexpected production receipt-key metadata: %+v", entry)
	}
	if entry.KeyID != expectedKeyID || entry.PublicKey != expectedPublicKey {
		t.Fatalf("production key pin changed: %+v", entry)
	}
	parsed, err := ParsePublicKey(entry.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KeyID != entry.KeyID || parsed.Base64URL != entry.PublicKey {
		t.Fatalf("production key identity mismatch: got %+v want key_id %s", parsed, entry.KeyID)
	}
}
