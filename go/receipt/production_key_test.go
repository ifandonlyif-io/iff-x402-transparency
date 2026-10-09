package receipt

import (
	"os"
	"regexp"
	"testing"
)

type pinnedKeyEntry struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Purpose   string `json:"purpose"`
	Status    string `json:"status"`
}

type pinnedDirectory struct {
	Schema  string           `json:"schema"`
	Issuer  string           `json:"issuer"`
	Enabled bool             `json:"enabled"`
	Keys    []pinnedKeyEntry `json:"keys"`
}

func readPinnedDirectory(t *testing.T, path string) pinnedDirectory {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateUniqueJSON(raw); err != nil {
		t.Fatal(err)
	}
	var directory pinnedDirectory
	if err := decodeStrict(raw, &directory); err != nil {
		t.Fatal(err)
	}
	return directory
}

// The 2026-09-01 snapshot is history: a v1 directory with the Ed25519 key.
func TestPublishedProductionReceiptKeyPin(t *testing.T) {
	const (
		expectedKeyID     = "sha256:0f872f79cd935ac2d764589c8283d35ae0ca02780faebee8862db85348fc5ceb"
		expectedPublicKey = "iVnUmYYy_PO_M3wFYWwc91wxVPU6VRyEcPr9iC4F230"
	)
	directory := readPinnedDirectory(t, "../../keys/service-receipt-production-2026-09-01.json")
	if directory.Schema != "https://ifandonlyif.io/schemas/service-receipt-key-directory-v1.json" ||
		directory.Issuer != "https://ifandonlyif.io" || !directory.Enabled || len(directory.Keys) != 1 {
		t.Fatalf("unexpected production receipt-key directory: %+v", directory)
	}
	entry := directory.Keys[0]
	if entry.Algorithm != AlgorithmEd25519 || entry.Purpose != "service-receipt-signing" || entry.Status != "current" {
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

// The 2026-10-10 snapshot is a key directory v2: ML-DSA-65 current, the former
// Ed25519 key previous.
func TestPublishedProductionReceiptKeyPinV2(t *testing.T) {
	const (
		mldsaKeyID   = "sha256:70be5c7a580fd0d89b34c4be79ed73fb7036ed3fb696223a1e271f61b9dcc217"
		ed25519KeyID = "sha256:0f872f79cd935ac2d764589c8283d35ae0ca02780faebee8862db85348fc5ceb"
	)
	directory := readPinnedDirectory(t, "../../keys/service-receipt-production-2026-10-10.json")
	if directory.Schema != KeyDirectorySchemaV2 || directory.Issuer != "https://ifandonlyif.io" ||
		!directory.Enabled || len(directory.Keys) != 2 {
		t.Fatalf("unexpected production receipt-key directory: %+v", directory)
	}
	current, previous := directory.Keys[0], directory.Keys[1]
	if current.KeyID != mldsaKeyID || current.Algorithm != AlgorithmMLDSA65 ||
		current.Status != "current" || current.Purpose != "service-receipt-signing" {
		t.Fatalf("unexpected current ML-DSA-65 key: %+v", current)
	}
	if previous.KeyID != ed25519KeyID || previous.Algorithm != AlgorithmEd25519 ||
		previous.Status != "previous" || previous.Purpose != "service-receipt-signing" {
		t.Fatalf("unexpected previous Ed25519 key: %+v", previous)
	}
	for _, entry := range directory.Keys {
		parsed, err := ParsePublicKey(entry.PublicKey)
		if err != nil {
			t.Fatalf("%s: %v", entry.KeyID, err)
		}
		if parsed.KeyID != entry.KeyID || parsed.Base64URL != entry.PublicKey || parsed.Algorithm != entry.Algorithm {
			t.Fatalf("key identity mismatch: got %+v want %+v", parsed, entry)
		}
	}
}

// TestProductionReceiptKeyDirectoryV2SchemaRules applies the rules of
// schemas/service-receipt-key-directory-v2.json (patterns, enums, the
// per-algorithm public-key length and the required fields) to the snapshot.
func TestProductionReceiptKeyDirectoryV2SchemaRules(t *testing.T) {
	directory := readPinnedDirectory(t, "../../keys/service-receipt-production-2026-10-10.json")
	keyIDPattern := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	publicKeyLength := map[string]int{AlgorithmEd25519: 43, AlgorithmMLDSA65: 2603}
	publicKeyPattern := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	for _, entry := range directory.Keys {
		length, knownAlgorithm := publicKeyLength[entry.Algorithm]
		switch {
		case !keyIDPattern.MatchString(entry.KeyID),
			!knownAlgorithm,
			!publicKeyPattern.MatchString(entry.PublicKey) || len(entry.PublicKey) != length,
			entry.Purpose != "service-receipt-signing",
			entry.Status != "current" && entry.Status != "previous" && entry.Status != "inactive":
			t.Fatalf("key entry violates the v2 directory schema: %.80s", entry.KeyID)
		}
	}
}
