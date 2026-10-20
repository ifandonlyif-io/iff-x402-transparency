package preflight

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDocumentLeafHashVectors(t *testing.T) {
	path := filepath.Join(filepath.Dir(findVectorsFile(t)), "observed_document_leaf_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Prefix  string `json:"leaf_data_prefix"`
		Length  int    `json:"leaf_data_length"`
		Vectors []struct {
			Name         string `json:"name"`
			DocumentHash string `json:"document_hash"`
			LeafData     string `json:"leaf_data"`
			LeafHash     string `json:"leaf_hash"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Prefix != DocumentLeafDomain || doc.Length != 62 || len(doc.Vectors) == 0 {
		t.Fatalf("unexpected document-leaf vector format: prefix=%q length=%d vectors=%d", doc.Prefix, doc.Length, len(doc.Vectors))
	}
	for _, vector := range doc.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			decoded, err := hex.DecodeString(vector.DocumentHash)
			if err != nil || len(decoded) != sha256.Size {
				t.Fatalf("invalid vector document hash: %q (%v)", vector.DocumentHash, err)
			}
			var documentHash [sha256.Size]byte
			copy(documentHash[:], decoded)
			leafData := append([]byte(DocumentLeafDomain), documentHash[:]...)
			if len(leafData) != doc.Length || hex.EncodeToString(leafData) != vector.LeafData {
				t.Fatal("leaf data does not match the published bytes")
			}
			got := DocumentLeafHash(documentHash)
			if hex.EncodeToString(got[:]) != vector.LeafHash {
				t.Fatalf("leaf hash = %x, want %s", got, vector.LeafHash)
			}
			// The same digest in the existing observation format must remain
			// distinct from the domain-prefixed document leaf.
			observationLeaf := sha256.Sum256(append([]byte{0}, documentHash[:]...))
			if got == observationLeaf {
				t.Fatal("document leaf matches the observation leaf of the same hash")
			}
		})
	}
}
