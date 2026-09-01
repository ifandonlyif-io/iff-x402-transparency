package receipt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"
)

type publishedExpected struct {
	SignatureValid     bool   `json:"signature_valid"`
	IssuerTrusted      bool   `json:"issuer_trusted"`
	Expired            bool   `json:"expired"`
	NotYetValid        bool   `json:"not_yet_valid"`
	EvidenceStatus     string `json:"evidence_status"`
	ComputeProofStatus string `json:"compute_proof_status"`
}

type publishedCase struct {
	CanonicalRequest string   `json:"canonical_request"`
	CanonicalSubject string   `json:"canonical_subject"`
	CanonicalPayload string   `json:"canonical_payload"`
	PayloadSHA256    string   `json:"payload_sha256"`
	SigningDigest    string   `json:"signing_digest_sha256"`
	KeyID            string   `json:"key_id"`
	PublicKey        string   `json:"public_key_base64url"`
	Signature        string   `json:"signature_base64url"`
	CurrentTime      string   `json:"current_time"`
	Envelope         Envelope `json:"envelope"`
	TrustedPolicy    struct {
		ExpectedIssuer string   `json:"expected_issuer"`
		TrustedKeyIDs  []string `json:"trusted_key_ids"`
	} `json:"trusted_policy"`
	Expected publishedExpected `json:"expected"`
}

type publishedVector struct {
	TestSeed         string        `json:"test_private_key_seed_base64"`
	CanonicalRequest string        `json:"canonical_request"`
	CanonicalSubject string        `json:"canonical_subject"`
	Valid            publishedCase `json:"valid"`
	EvidenceCompute  publishedCase `json:"evidence_compute"`
}

func loadPublishedVector(t *testing.T) publishedVector {
	t.Helper()
	raw, err := os.ReadFile("../../spec/testdata/service_receipt_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector publishedVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func TestPublishedServiceReceiptVectors(t *testing.T) {
	vector := loadPublishedVector(t)
	signer, err := NewSigner(vector.TestSeed)
	if err != nil {
		t.Fatal(err)
	}

	baseline := vector.Valid
	baseline.CanonicalRequest = vector.CanonicalRequest
	baseline.CanonicalSubject = vector.CanonicalSubject
	t.Run("baseline", func(t *testing.T) {
		verifyPublishedCase(t, signer, baseline, baseline.TrustedPolicy, baseline.CurrentTime)
	})

	t.Run("evidence_and_compute_descriptors", func(t *testing.T) {
		verifyPublishedCase(t, signer, vector.EvidenceCompute, vector.EvidenceCompute.TrustedPolicy, vector.EvidenceCompute.CurrentTime)
		assertEvidenceMatchesTransparencyVector(t, vector.EvidenceCompute.Envelope)
	})
}

func verifyPublishedCase(t *testing.T, signer *Signer, testCase publishedCase, policy struct {
	ExpectedIssuer string   `json:"expected_issuer"`
	TrustedKeyIDs  []string `json:"trusted_key_ids"`
}, currentTime string) {
	t.Helper()
	payloadBytes := []byte(testCase.CanonicalPayload)
	payloadHash := sha256.Sum256(payloadBytes)
	if got := hex.EncodeToString(payloadHash[:]); got != testCase.PayloadSHA256 {
		t.Fatalf("payload hash: got %s", got)
	}
	digest := signingDigest(payloadBytes)
	if got := hex.EncodeToString(digest[:]); got != testCase.SigningDigest {
		t.Fatalf("signing digest: got %s", got)
	}
	if decoded, err := base64.RawURLEncoding.Strict().DecodeString(testCase.Envelope.Payload); err != nil || string(decoded) != testCase.CanonicalPayload {
		t.Fatalf("published envelope payload does not contain the canonical bytes: %v", err)
	}
	if testCase.Envelope.Schema != Schema || testCase.Envelope.PayloadSHA256 != testCase.PayloadSHA256 ||
		testCase.Envelope.Signature.Algorithm != Algorithm || testCase.Envelope.Signature.KeyID != testCase.KeyID ||
		testCase.Envelope.Signature.PublicKey != testCase.PublicKey || testCase.Envelope.Signature.Value != testCase.Signature {
		t.Fatal("published envelope duplicates disagree with their component fields")
	}
	if signer.KeyID() != testCase.KeyID || signer.PublicKeyBase64URL() != testCase.PublicKey {
		t.Fatal("published key identity does not reproduce from the test seed")
	}

	var payload Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatal(err)
	}
	reproduced, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	if reproduced != testCase.Envelope {
		t.Fatalf("published envelope drifted:\n got: %+v\nwant: %+v", reproduced, testCase.Envelope)
	}

	now, err := time.Parse(TimestampLayout, currentTime)
	if err != nil {
		t.Fatal(err)
	}
	envelopeJSON, err := json.Marshal(testCase.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyJSON(envelopeJSON, VerifyOptions{
		TrustedKeyIDs: policy.TrustedKeyIDs, ExpectedIssuer: policy.ExpectedIssuer, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.SignatureValid != testCase.Expected.SignatureValid ||
		verified.IssuerTrusted != testCase.Expected.IssuerTrusted || verified.Expired != testCase.Expected.Expired ||
		verified.NotYetValid != testCase.Expected.NotYetValid || verified.EvidenceStatus != testCase.Expected.EvidenceStatus ||
		verified.ComputeProofStatus != testCase.Expected.ComputeProofStatus {
		t.Fatalf("unexpected published vector result: %+v", verified)
	}
	if string(verified.Subject) != testCase.CanonicalSubject {
		t.Fatal("subject vector drifted")
	}
	requestHash := RequestHash([]byte(testCase.CanonicalRequest))
	if payload.RequestSHA256 != hex.EncodeToString(requestHash[:]) {
		t.Fatal("request hash vector drifted")
	}
}

func assertEvidenceMatchesTransparencyVector(t *testing.T, envelope Envelope) {
	t.Helper()
	type logLeaf struct {
		Index      uint64 `json:"index"`
		ReportHash string `json:"report_hash"`
		LeafHash   string `json:"leaf_hash"`
	}
	var logVector struct {
		Leaves         []logLeaf `json:"leaves"`
		TreeSize       uint64    `json:"tree_size"`
		RootHash       string    `json:"root_hash"`
		SignedTreeHead struct {
			LogID      string `json:"log_id"`
			SHA256Hash string `json:"sha256_hash"`
		} `json:"signed_tree_head"`
	}
	raw, err := os.ReadFile("../../spec/testdata/log_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &logVector); err != nil {
		t.Fatal(err)
	}
	verification, err := Verify(envelope, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	evidence := verification.Payload.Evidence
	if evidence == nil {
		t.Fatal("descriptor vector must contain evidence")
	}
	var leaf *logLeaf
	for index := range logVector.Leaves {
		if strconv.FormatUint(logVector.Leaves[index].Index, 10) == evidence.LogIndex {
			leaf = &logVector.Leaves[index]
			break
		}
	}
	if leaf == nil || leaf.ReportHash != evidence.ReportHash || leaf.LeafHash != evidence.LeafHash {
		t.Fatal("receipt evidence does not match its referenced transparency-log leaf")
	}
	if evidence.TreeSize != strconv.FormatUint(logVector.TreeSize, 10) || evidence.STHRootHash != logVector.RootHash ||
		evidence.LogID != logVector.SignedTreeHead.LogID || evidence.STHSHA256Hash != logVector.SignedTreeHead.SHA256Hash {
		t.Fatal("receipt evidence does not match its referenced signed tree head")
	}
}
