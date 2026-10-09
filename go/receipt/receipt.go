// Package receipt implements the IFF Service Receipt envelopes. Version 2
// (ML-DSA-65) is issued; versions 1 (Ed25519) and 2 are both verified. It
// intentionally depends only on the Go standard library (Go 1.27 or later, for
// crypto/mldsa) so the experimental artifact can be verified without importing
// the IFF server or its runtime dependencies.
package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// SchemaV1 and SchemaV2 identify both the signed payload and its detached
	// envelope. The schema decides the version and, with it, the algorithm.
	SchemaV1 = "https://ifandonlyif.io/schemas/service-receipt-v1.json"
	SchemaV2 = "https://ifandonlyif.io/schemas/service-receipt-v2.json"

	// Schema is the schema of newly issued receipts.
	Schema = SchemaV2

	AlgorithmEd25519 = "Ed25519"
	AlgorithmMLDSA65 = "ML-DSA-65"
	// Algorithm is the algorithm of newly issued receipts.
	Algorithm = AlgorithmMLDSA65

	// DomainV1 is hashed with the canonical payload before Ed25519 signing.
	// DomainV2 is the line prepended to the payload digest to form the
	// ML-DSA-65 message. Each prevents a signature made for another IFF
	// artifact from being accepted as a service receipt.
	DomainV1 = "iff-service-receipt/v1\n"
	DomainV2 = "iff-service-receipt/v2\n"
	Domain   = DomainV2

	// KeyDirectorySchemaV2 identifies the v2 issuer key directory.
	KeyDirectorySchemaV2 = "https://ifandonlyif.io/schemas/service-receipt-key-directory-v2.json"

	ed25519PublicKeySize = ed25519.PublicKeySize
	ed25519SignatureSize = ed25519.SignatureSize
	mldsa65PublicKeySize = 1952
	mldsa65SignatureSize = 3309
	seedEncodedLength    = 43

	requestHashDomain = "iff-service-receipt/request/v1\n"
	subjectHashDomain = "iff-service-receipt/subject/v1\n"

	TimestampLayout = "2006-01-02T15:04:05.000000Z"

	maxEnvelopeBytes = 256 << 10
	maxPayloadBytes  = 192 << 10
	maxSubjectBytes  = 128 << 10
	maxJSONDepth     = 128
)

var (
	ErrDisabled          = errors.New("service receipt signing is disabled")
	ErrInvalidEnvelope   = errors.New("invalid service receipt envelope")
	ErrInvalidPayload    = errors.New("invalid service receipt payload")
	ErrInvalidSignature  = errors.New("invalid service receipt signature")
	ErrUnsupportedSchema = errors.New("unsupported service receipt schema")
	rawBase64URL         = base64.RawURLEncoding.Strict()
)

// Envelope carries canonical payload bytes and a detached signature.
// Payload and all key material use unpadded base64url so the same bytes can be
// copied through URLs, JSON, and terminals unchanged.
type Envelope struct {
	Schema        string    `json:"schema"`
	Payload       string    `json:"payload"`
	PayloadSHA256 string    `json:"payload_sha256"`
	Signature     Signature `json:"signature"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Value     string `json:"value"`
}

// PublicKey is the normalized form used by issuer key directories and key
// rotation overlap lists.
type PublicKey struct {
	KeyID     string
	Algorithm string
	Base64URL string
}

// Payload is the canonical, signed receipt statement. RequestSHA256 commits
// to the service-specific canonical request projection. Subject contains the
// exact response bytes, so an offline verifier never has to reproduce another
// language's JSON serialization before it can inspect what was signed.
type Payload struct {
	Schema           string           `json:"schema"`
	ReceiptID        string           `json:"receipt_id"`
	Issuer           string           `json:"issuer"`
	Service          string           `json:"service"`
	IssuedAt         string           `json:"issued_at"`
	ExpiresAt        string           `json:"expires_at"`
	Nonce            *string          `json:"nonce"`
	RequestSHA256    string           `json:"request_sha256"`
	SubjectMediaType string           `json:"subject_media_type"`
	SubjectSHA256    string           `json:"subject_sha256"`
	Subject          string           `json:"subject"`
	Evidence         *EvidenceBinding `json:"evidence"`
	ComputeProof     *ComputeProof    `json:"compute_proof"`
}

// EvidenceBinding points to evidence that is already covered by the signed
// response. It does not claim the service receipt itself is in the log.
type EvidenceBinding struct {
	ObservationID string `json:"observation_id"`
	ReportHash    string `json:"report_hash"`
	LeafHash      string `json:"leaf_hash"`
	LogID         string `json:"log_id"`
	LogIndex      string `json:"log_index"`
	TreeSize      string `json:"tree_size"`
	STHRootHash   string `json:"sth_root_hash"`
	STHSHA256Hash string `json:"sth_sha256_hash"`
}

// ComputeProof is retained as part of the fixed v1 wire format. The current
// IFF issuer leaves it null, and the base verifier only binds a non-null
// descriptor's bytes; it does not validate an external proof system.
type ComputeProof struct {
	Type           string `json:"type"`
	Provider       string `json:"provider"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	ArtifactURI    string `json:"artifact_uri"`
	Verifier       string `json:"verifier"`
}

// Signer signs Service Receipt v2 envelopes with ML-DSA-65. There is no
// Ed25519 signer: v1 receipts are verified but never issued.
type Signer struct {
	privateKey *mldsa.PrivateKey
	publicKey  []byte
}

// Verification separates cryptographic integrity from issuer trust and
// time-based action eligibility. A receipt can remain a valid historical
// signature after ExpiresAt, while no longer being fresh enough for an action.
type Verification struct {
	Payload            Payload `json:"payload"`
	PayloadSHA256      string  `json:"payload_sha256"`
	Algorithm          string  `json:"algorithm"`
	KeyID              string  `json:"key_id"`
	SignatureValid     bool    `json:"signature_valid"`
	IssuerTrusted      bool    `json:"issuer_trusted"`
	Expired            bool    `json:"expired"`
	NotYetValid        bool    `json:"not_yet_valid"`
	ComputeProofStatus string  `json:"compute_proof_status"`
	EvidenceStatus     string  `json:"evidence_status"`
	Subject            []byte  `json:"-"`
}

type VerifyOptions struct {
	// TrustedKeyIDs is an explicit allowlist obtained through a separately
	// authenticated channel. The public key embedded in an envelope proves
	// self-consistency only and never establishes issuer trust by itself.
	TrustedKeyIDs []string
	// ExpectedIssuer must match the signed issuer exactly. A trusted key ID
	// without an expected issuer never establishes issuer trust, because the
	// same embedded key could otherwise be replayed under another issuer name.
	ExpectedIssuer string
	Now            time.Time
	ClockSkew      time.Duration
}

// ValidateUniqueJSON rejects malformed or non-interoperable UTF-8 JSON and
// duplicate object keys at any depth. Service adapters and CLIs use it before
// extracting an embedded envelope so decoder replacement and last-key-wins
// parsing cannot hide substitutions.
func ValidateUniqueJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON must be valid UTF-8")
	}
	if !hasOnlyPairedJSONSurrogates(raw) {
		return errors.New("JSON strings must not contain unpaired Unicode surrogates")
	}
	return rejectDuplicateJSONKeys(raw)
}

// NewSigner loads a 32-byte ML-DSA-65 seed written as canonical unpadded
// base64url (exactly 43 characters). An empty value creates a disabled signer,
// which keeps receipt issuance opt-in at deployment time. Errors never contain
// the value.
func NewSigner(encodedSeed string) (*Signer, error) {
	if encodedSeed == "" {
		return &Signer{}, nil
	}
	seed, err := rawBase64URL.DecodeString(encodedSeed)
	if err != nil || len(encodedSeed) != seedEncodedLength || len(seed) != mldsa.PrivateKeySize ||
		rawBase64URL.EncodeToString(seed) != encodedSeed {
		return nil, errors.New("signing key must be a 32-byte ML-DSA-65 seed as canonical unpadded base64url (43 characters)")
	}
	privateKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		return nil, errors.New("invalid ML-DSA-65 seed")
	}
	return &Signer{privateKey: privateKey, publicKey: privateKey.PublicKey().Bytes()}, nil
}

func (signer *Signer) Enabled() bool {
	return signer != nil && signer.privateKey != nil
}

func (signer *Signer) PublicKeyBase64URL() string {
	if !signer.Enabled() {
		return ""
	}
	return rawBase64URL.EncodeToString(signer.publicKey)
}

func (signer *Signer) KeyID() string {
	if !signer.Enabled() {
		return ""
	}
	return KeyID(signer.publicKey)
}

// NewPayload constructs a canonical receipt payload and hashes the exact
// request projection and response bytes supplied by the service adapter.
func NewPayload(
	issuer, service string,
	issuedAt, expiresAt time.Time,
	nonce *string,
	requestProjection, subject []byte,
	evidence *EvidenceBinding,
) (Payload, error) {
	normalizedIssuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return Payload{}, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	receiptID, err := newReceiptID()
	if err != nil {
		return Payload{}, err
	}
	requestHash := RequestHash(requestProjection)
	subjectHash := SubjectHash(subject)
	payload := Payload{
		Schema:           Schema,
		ReceiptID:        receiptID,
		Issuer:           normalizedIssuer,
		Service:          service,
		IssuedAt:         FormatTimestamp(issuedAt),
		ExpiresAt:        FormatTimestamp(expiresAt),
		Nonce:            cloneStringPointer(nonce),
		RequestSHA256:    hex.EncodeToString(requestHash[:]),
		SubjectMediaType: "application/json",
		SubjectSHA256:    hex.EncodeToString(subjectHash[:]),
		Subject:          rawBase64URL.EncodeToString(subject),
		Evidence:         evidence,
		ComputeProof:     nil,
	}
	if err := validatePayload(payload, Schema); err != nil {
		return Payload{}, err
	}
	return payload, nil
}

// Sign issues a Service Receipt v2 envelope (hedged ML-DSA-65, empty context).
func (signer *Signer) Sign(payload Payload) (Envelope, error) {
	return signer.sign(payload, false)
}

// sign is Sign with an optional deterministic mode that exists only so the
// published test vectors can be reproduced byte for byte.
func (signer *Signer) sign(payload Payload, deterministic bool) (Envelope, error) {
	if !signer.Enabled() {
		return Envelope{}, ErrDisabled
	}
	if err := validatePayload(payload, SchemaV2); err != nil {
		return Envelope{}, err
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal receipt payload: %w", err)
	}
	if len(payloadBytes) > maxPayloadBytes {
		return Envelope{}, fmt.Errorf("%w: payload exceeds %d bytes", ErrInvalidPayload, maxPayloadBytes)
	}
	payloadHash := sha256.Sum256(payloadBytes)
	message := signingMessageV2(payloadBytes)
	var signature []byte
	if deterministic {
		signature, err = signer.privateKey.SignDeterministic(message, &mldsa.Options{})
	} else {
		signature, err = signer.privateKey.Sign(rand.Reader, message, &mldsa.Options{})
	}
	if err != nil {
		return Envelope{}, fmt.Errorf("sign receipt: %w", err)
	}
	return Envelope{
		Schema:        SchemaV2,
		Payload:       rawBase64URL.EncodeToString(payloadBytes),
		PayloadSHA256: hex.EncodeToString(payloadHash[:]),
		Signature: Signature{
			Algorithm: AlgorithmMLDSA65,
			KeyID:     signer.KeyID(),
			PublicKey: signer.PublicKeyBase64URL(),
			Value:     rawBase64URL.EncodeToString(signature),
		},
	}, nil
}

// VerifyJSON strictly parses and verifies a receipt envelope.
func VerifyJSON(raw []byte, options VerifyOptions) (Verification, error) {
	if len(raw) == 0 || len(raw) > maxEnvelopeBytes {
		return Verification{}, fmt.Errorf("%w: envelope size is invalid", ErrInvalidEnvelope)
	}
	if err := ValidateUniqueJSON(raw); err != nil {
		return Verification{}, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if err := validateEnvelopePropertyNames(raw); err != nil {
		return Verification{}, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	var envelope Envelope
	if err := decodeStrict(raw, &envelope); err != nil {
		return Verification{}, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	return Verify(envelope, options)
}

// Verify validates integrity and returns separately evaluated trust/freshness
// state. It never treats an embedded public key or compute-proof descriptor as
// proof of issuer identity or execution environment.
func Verify(envelope Envelope, options VerifyOptions) (Verification, error) {
	// The schema decides the version; the algorithm must match it.
	var algorithm string
	var publicKeySize, signatureSize int
	switch envelope.Schema {
	case SchemaV1:
		algorithm, publicKeySize, signatureSize = AlgorithmEd25519, ed25519PublicKeySize, ed25519SignatureSize
	case SchemaV2:
		algorithm, publicKeySize, signatureSize = AlgorithmMLDSA65, mldsa65PublicKeySize, mldsa65SignatureSize
	default:
		return Verification{}, ErrUnsupportedSchema
	}
	if envelope.Signature.Algorithm != algorithm {
		return Verification{}, fmt.Errorf("%w: signature algorithm must be %s for this schema", ErrInvalidEnvelope, algorithm)
	}
	payloadBytes, err := rawBase64URL.DecodeString(envelope.Payload)
	if err != nil || len(payloadBytes) == 0 || len(payloadBytes) > maxPayloadBytes {
		return Verification{}, fmt.Errorf("%w: payload is not valid base64url or has invalid size", ErrInvalidEnvelope)
	}
	payloadHash := sha256.Sum256(payloadBytes)
	payloadHashHex := hex.EncodeToString(payloadHash[:])
	if envelope.PayloadSHA256 != payloadHashHex {
		return Verification{}, fmt.Errorf("%w: payload_sha256 mismatch", ErrInvalidEnvelope)
	}

	publicKey, err := rawBase64URL.DecodeString(envelope.Signature.PublicKey)
	if err != nil || len(publicKey) != publicKeySize {
		return Verification{}, fmt.Errorf("%w: public_key must be a %d-byte base64url %s key", ErrInvalidEnvelope, publicKeySize, algorithm)
	}
	keyID := KeyID(publicKey)
	if envelope.Signature.KeyID != keyID {
		return Verification{}, fmt.Errorf("%w: key_id mismatch", ErrInvalidEnvelope)
	}
	signature, err := rawBase64URL.DecodeString(envelope.Signature.Value)
	if err != nil || len(signature) != signatureSize {
		return Verification{}, fmt.Errorf("%w: value must be a %d-byte base64url %s signature", ErrInvalidEnvelope, signatureSize, algorithm)
	}
	if err := verifySignature(algorithm, publicKey, payloadBytes, signature); err != nil {
		return Verification{}, err
	}

	var payload Payload
	if err := decodeStrict(payloadBytes, &payload); err != nil {
		return Verification{}, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	if err := rejectDuplicateJSONKeys(payloadBytes); err != nil {
		return Verification{}, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, payloadBytes) {
		return Verification{}, fmt.Errorf("%w: payload is not the canonical fixed-order JSON encoding", ErrInvalidPayload)
	}
	if payload.Schema != envelope.Schema {
		return Verification{}, fmt.Errorf("%w: payload schema does not match envelope schema", ErrUnsupportedSchema)
	}
	if err := validatePayload(payload, envelope.Schema); err != nil {
		return Verification{}, err
	}
	subject, _ := rawBase64URL.DecodeString(payload.Subject)

	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	clockSkew := options.ClockSkew
	if clockSkew < 0 {
		clockSkew = 0
	}
	issuedAt, _ := time.Parse(TimestampLayout, payload.IssuedAt)
	expiresAt, _ := time.Parse(TimestampLayout, payload.ExpiresAt)
	result := Verification{
		Payload:        payload,
		PayloadSHA256:  payloadHashHex,
		Algorithm:      algorithm,
		KeyID:          keyID,
		SignatureValid: true,
		IssuerTrusted: options.ExpectedIssuer != "" && payload.Issuer == options.ExpectedIssuer &&
			containsString(options.TrustedKeyIDs, keyID),
		Expired:            !now.Before(expiresAt.Add(clockSkew)),
		NotYetValid:        now.Add(clockSkew).Before(issuedAt),
		ComputeProofStatus: "absent",
		EvidenceStatus:     "absent",
		Subject:            subject,
	}
	if payload.ComputeProof != nil {
		result.ComputeProofStatus = "descriptor_signed_unverified"
	}
	if payload.Evidence != nil {
		result.EvidenceStatus = "referenced_unverified"
	}
	return result, nil
}

func FormatTimestamp(value time.Time) string {
	return value.UTC().Format(TimestampLayout)
}

// NormalizeIssuer applies the service-adapter input normalization used before
// an issuer is signed, then requires the result to be a canonical issuer.
// This preserves the established acceptance of surrounding whitespace and
// trailing slashes without allowing noncanonical signed issuer bytes.
func NormalizeIssuer(value string) (string, error) {
	normalized := strings.TrimRight(strings.TrimSpace(value), "/")
	if err := ValidateIssuer(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

// ValidateIssuer requires the canonical receipt issuer form: an HTTPS origin,
// or a loopback HTTP origin for local development, with no credentials, path,
// query, fragment, default port, uppercase host, or noncanonical IP spelling.
func ValidateIssuer(value string) error {
	if !validIssuer(value) {
		return errors.New("issuer must be a canonical HTTPS origin or loopback HTTP origin")
	}
	return nil
}

// ValidateNonce applies the portable v1 nonce grammar used by service
// adapters: 1-128 ASCII letters, digits, hyphen, underscore, dot, or colon.
func ValidateNonce(value string) error {
	if !validNonce(value) {
		return fmt.Errorf("nonce must contain 1-128 letters, digits, hyphens, underscores, dots, or colons")
	}
	return nil
}

// AlgorithmForPublicKey selects the algorithm from the exact raw key length.
func AlgorithmForPublicKey(raw []byte) (string, error) {
	switch len(raw) {
	case ed25519PublicKeySize:
		return AlgorithmEd25519, nil
	case mldsa65PublicKeySize:
		return AlgorithmMLDSA65, nil
	}
	return "", errors.New("public key must decode to 32 Ed25519 bytes or 1952 ML-DSA-65 bytes")
}

func KeyID(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// ParsePublicKey accepts padded/unpadded standard or URL-safe base64 and
// returns the one canonical unpadded base64url representation. The algorithm
// is selected from the decoded length only: 32 bytes is Ed25519, 1952 bytes is
// ML-DSA-65, anything else is rejected.
func ParsePublicKey(encoded string) (PublicKey, error) {
	raw, err := decodeAnyBase64(strings.TrimSpace(encoded))
	if err != nil {
		return PublicKey{}, errors.New("public key must decode to 32 Ed25519 bytes or 1952 ML-DSA-65 bytes")
	}
	algorithm, err := AlgorithmForPublicKey(raw)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{
		KeyID:     KeyID(raw),
		Algorithm: algorithm,
		Base64URL: rawBase64URL.EncodeToString(raw),
	}, nil
}

// RequestHash and SubjectHash use different domains so the same bytes cannot
// be moved between the two receipt roles without changing the digest.
func RequestHash(value []byte) [sha256.Size]byte {
	return hashWithDomain(requestHashDomain, value)
}

func SubjectHash(value []byte) [sha256.Size]byte {
	return hashWithDomain(subjectHashDomain, value)
}

func hashWithDomain(domain string, value []byte) [sha256.Size]byte {
	input := make([]byte, 0, len(domain)+len(value))
	input = append(input, domain...)
	input = append(input, value...)
	return sha256.Sum256(input)
}

// SubjectMatches compares candidate bytes with the exact signed response.
// Verifier UIs must render Verification.Subject as authoritative unless this
// returns true for an accompanying outer response.
func (verification Verification) SubjectMatches(candidate []byte) bool {
	return bytes.Equal(verification.Subject, candidate)
}

// SubjectMatchesJSON compares the signed subject with an accompanying outer
// result as JSON values. It is intended for envelopes embedded in a larger
// response, where removing service_receipt necessarily changes field order.
// Duplicate keys are rejected on both sides before semantic comparison.
func (verification Verification) SubjectMatchesJSON(candidate []byte) bool {
	if ValidateUniqueJSON(verification.Subject) != nil || ValidateUniqueJSON(candidate) != nil {
		return false
	}
	left, err := decodeJSONValue(verification.Subject)
	if err != nil {
		return false
	}
	right, err := decodeJSONValue(candidate)
	return err == nil && reflect.DeepEqual(left, right)
}

// signingDigest is the v1 Ed25519 message: SHA-256(DomainV1 || payload).
func signingDigest(payload []byte) [sha256.Size]byte {
	input := make([]byte, 0, len(DomainV1)+len(payload))
	input = append(input, DomainV1...)
	input = append(input, payload...)
	return sha256.Sum256(input)
}

// signingMessageV2 is the v2 ML-DSA-65 message: DomainV2 || SHA-256(payload).
func signingMessageV2(payload []byte) []byte {
	digest := sha256.Sum256(payload)
	message := make([]byte, 0, len(DomainV2)+len(digest))
	message = append(message, DomainV2...)
	return append(message, digest[:]...)
}

func verifySignature(algorithm string, publicKey, payload, signature []byte) error {
	switch algorithm {
	case AlgorithmEd25519:
		digest := signingDigest(payload)
		if ed25519.Verify(ed25519.PublicKey(publicKey), digest[:], signature) {
			return nil
		}
	case AlgorithmMLDSA65:
		key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), publicKey)
		if err != nil {
			return fmt.Errorf("%w: public_key is not a valid ML-DSA-65 key", ErrInvalidEnvelope)
		}
		if mldsa.Verify(key, signingMessageV2(payload), signature, &mldsa.Options{}) == nil {
			return nil
		}
	}
	return ErrInvalidSignature
}

func validatePayload(payload Payload, schema string) error {
	if payload.Schema != schema {
		return ErrUnsupportedSchema
	}
	if !validReceiptID(payload.ReceiptID) {
		return fmt.Errorf("%w: receipt_id is invalid", ErrInvalidPayload)
	}
	if err := ValidateIssuer(payload.Issuer); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	if !validService(payload.Service) {
		return fmt.Errorf("%w: service is invalid", ErrInvalidPayload)
	}
	issuedAt, err := time.Parse(TimestampLayout, payload.IssuedAt)
	if err != nil || FormatTimestamp(issuedAt) != payload.IssuedAt {
		return fmt.Errorf("%w: issued_at must be UTC with six fractional digits", ErrInvalidPayload)
	}
	expiresAt, err := time.Parse(TimestampLayout, payload.ExpiresAt)
	if err != nil || FormatTimestamp(expiresAt) != payload.ExpiresAt || !expiresAt.After(issuedAt) {
		return fmt.Errorf("%w: expires_at must be canonical and later than issued_at", ErrInvalidPayload)
	}
	if payload.Nonce != nil && !validNonce(*payload.Nonce) {
		return fmt.Errorf("%w: nonce is invalid", ErrInvalidPayload)
	}
	if !validLowerHexDigest(payload.RequestSHA256) || !validLowerHexDigest(payload.SubjectSHA256) {
		return fmt.Errorf("%w: request/subject hashes must be lowercase SHA-256 hex", ErrInvalidPayload)
	}
	if payload.SubjectMediaType != "application/json" {
		return fmt.Errorf("%w: unsupported subject_media_type", ErrInvalidPayload)
	}
	subject, err := rawBase64URL.DecodeString(payload.Subject)
	if err != nil || len(subject) == 0 || len(subject) > maxSubjectBytes ||
		!utf8.Valid(subject) || !json.Valid(subject) || !hasOnlyPairedJSONSurrogates(subject) {
		return fmt.Errorf("%w: subject must be bounded, interoperable UTF-8 JSON", ErrInvalidPayload)
	}
	if trimmed := bytes.TrimSpace(subject); len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("%w: subject JSON must be an object", ErrInvalidPayload)
	}
	if err := rejectDuplicateJSONKeys(subject); err != nil {
		return fmt.Errorf("%w: subject JSON is ambiguous: %v", ErrInvalidPayload, err)
	}
	subjectHash := SubjectHash(subject)
	if payload.SubjectSHA256 != hex.EncodeToString(subjectHash[:]) {
		return fmt.Errorf("%w: subject_sha256 mismatch", ErrInvalidPayload)
	}
	if payload.Evidence != nil {
		logIndex, indexErr := strconv.ParseUint(payload.Evidence.LogIndex, 10, 64)
		treeSize, sizeErr := strconv.ParseUint(payload.Evidence.TreeSize, 10, 64)
		if !validUUID(payload.Evidence.ObservationID) || !validLowerHex(payload.Evidence.LogID, 16) ||
			!validLowerHexDigest(payload.Evidence.ReportHash) || !validLowerHexDigest(payload.Evidence.LeafHash) ||
			!validLowerHexDigest(payload.Evidence.STHRootHash) || !validLowerHexDigest(payload.Evidence.STHSHA256Hash) ||
			indexErr != nil || sizeErr != nil || treeSize <= logIndex ||
			canonicalDecimal(payload.Evidence.LogIndex, logIndex) == false || canonicalDecimal(payload.Evidence.TreeSize, treeSize) == false {
			return fmt.Errorf("%w: evidence binding is invalid", ErrInvalidPayload)
		}
		reportHash, _ := hex.DecodeString(payload.Evidence.ReportHash)
		leafInput := append([]byte{0x00}, reportHash...)
		expectedLeaf := sha256.Sum256(leafInput)
		if payload.Evidence.LeafHash != hex.EncodeToString(expectedLeaf[:]) {
			return fmt.Errorf("%w: evidence leaf_hash does not bind report_hash", ErrInvalidPayload)
		}
	}
	if payload.ComputeProof != nil {
		if !validMetadataToken(payload.ComputeProof.Type) || !validMetadataToken(payload.ComputeProof.Provider) ||
			!validLowerHexDigest(payload.ComputeProof.ArtifactSHA256) || !validMetadataToken(payload.ComputeProof.Verifier) {
			return fmt.Errorf("%w: compute_proof is invalid", ErrInvalidPayload)
		}
		if payload.ComputeProof.ArtifactURI != "" {
			parsed, parseErr := url.ParseRequestURI(payload.ComputeProof.ArtifactURI)
			if parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
				!safeCanonicalString(payload.ComputeProof.ArtifactURI) {
				return fmt.Errorf("%w: compute proof artifact_uri must be HTTPS", ErrInvalidPayload)
			}
		}
	}
	return nil
}

func validIssuer(raw string) bool {
	if !safeCanonicalString(raw) {
		return false
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return false
	}
	hostname := parsed.Hostname()
	if hostname == "" || strings.Contains(hostname, "%") {
		return false
	}
	canonicalHostname := strings.ToLower(hostname)
	if ip := net.ParseIP(hostname); ip != nil {
		canonicalHostname = ip.String()
	} else if !validDNSHostname(hostname) || hasIPv4NumberEnding(hostname) {
		// WHATWG URL parsing treats these as IPv4 candidates (for example
		// 127.1 or 2130706433), while net/url otherwise leaves them looking
		// like DNS names. The explicit DNS grammar also rejects host characters
		// that Go and WHATWG parse differently, such as stray brackets, braces,
		// backticks, and underscores.
		return false
	}
	port := parsed.Port()
	if port != "" {
		parsedPort, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || strconv.FormatUint(parsedPort, 10) != port {
			return false
		}
	}
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	canonicalHost := canonicalHostname
	if port != "" {
		canonicalHost = net.JoinHostPort(canonicalHostname, port)
	} else if strings.Contains(canonicalHostname, ":") {
		canonicalHost = "[" + canonicalHostname + "]"
	}
	if raw != parsed.Scheme+"://"+canonicalHost {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return hostname == "localhost" || (net.ParseIP(hostname) != nil && net.ParseIP(hostname).IsLoopback())
}

func validDNSHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 || strings.HasSuffix(hostname, ".") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func hasIPv4NumberEnding(hostname string) bool {
	trimmed := strings.TrimSuffix(hostname, ".")
	lastLabel := trimmed
	if dot := strings.LastIndexByte(trimmed, '.'); dot >= 0 {
		lastLabel = trimmed[dot+1:]
	}
	if lastLabel == "" {
		return false
	}
	if strings.HasPrefix(lastLabel, "0x") || strings.HasPrefix(lastLabel, "0X") {
		if len(lastLabel) == 2 {
			// WHATWG's IPv4-number parser treats an empty hexadecimal
			// payload as zero, so even a bare 0x is not a DNS label.
			return true
		}
		for _, character := range lastLabel[2:] {
			if !((character >= '0' && character <= '9') ||
				(character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
				return false
			}
		}
		return true
	}
	for _, character := range lastLabel {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validService(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') ||
			(index > 0 && (char == '-' || char == '_' || char == '.')) {
			continue
		}
		return false
	}
	return true
}

func validMetadataToken(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("-_.:/@", char) {
			continue
		}
		return false
	}
	return true
}

func safeCanonicalString(value string) bool {
	for _, char := range value {
		if char < 0x20 || char > 0x7e || strings.ContainsRune("\\\"<>&", char) {
			return false
		}
	}
	return true
}

// hasOnlyPairedJSONSurrogates rejects the lone UTF-16 surrogate escapes that
// RFC 8259 identifies as unpredictable between implementations. Literal
// non-BMP UTF-8 and correctly paired \uD800-\uDBFF + \uDC00-\uDFFF escapes
// remain valid. Callers run utf8.Valid and json.Valid separately.
func hasOnlyPairedJSONSurrogates(raw []byte) bool {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(raw) {
				continue
			}
			if raw[index+1] != 'u' {
				index++
				continue
			}
			value, ok := jsonHexQuad(raw, index+2)
			if !ok {
				continue
			}
			switch {
			case value >= 0xd800 && value <= 0xdbff:
				if index+11 >= len(raw) || raw[index+6] != '\\' || raw[index+7] != 'u' {
					return false
				}
				low, lowOK := jsonHexQuad(raw, index+8)
				if !lowOK || low < 0xdc00 || low > 0xdfff {
					return false
				}
				index += 11
			case value >= 0xdc00 && value <= 0xdfff:
				return false
			default:
				index += 5
			}
		}
	}
	return true
}

func jsonHexQuad(raw []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, character := range raw[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func validNonce(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("-_.:", char) {
			continue
		}
		return false
	}
	return true
}

func validReceiptID(value string) bool {
	if !strings.HasPrefix(value, "sr1_") {
		return false
	}
	raw, err := rawBase64URL.DecodeString(strings.TrimPrefix(value, "sr1_"))
	return err == nil && len(raw) == 18
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func validLowerHexDigest(value string) bool {
	return validLowerHex(value, sha256.Size)
}

func validLowerHex(value string, byteLength int) bool {
	if len(value) != byteLength*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == byteLength
}

func newReceiptID() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate receipt id: %w", err)
	}
	return "sr1_" + rawBase64URL.EncodeToString(raw), nil
}

func decodeStrict(raw []byte, destination interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func decodeJSONValue(raw []byte) (interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}
	return value, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		if depth >= maxJSONDepth {
			return fmt.Errorf("JSON nesting exceeds %d containers", maxJSONDepth)
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateEnvelopePropertyNames(raw []byte) error {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if err := requireExactKeys(envelope, "schema", "payload", "payload_sha256", "signature"); err != nil {
		return err
	}
	var signature map[string]json.RawMessage
	if err := json.Unmarshal(envelope["signature"], &signature); err != nil {
		return err
	}
	return requireExactKeys(signature, "algorithm", "key_id", "public_key", "value")
}

func requireExactKeys(object map[string]json.RawMessage, expected ...string) error {
	if len(object) != len(expected) {
		return errors.New("object has missing or unexpected property names")
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			return fmt.Errorf("required property %q is missing or misspelled", key)
		}
	}
	return nil
}

func canonicalDecimal(raw string, value uint64) bool {
	return raw == strconv.FormatUint(value, 10)
}

func decodeAnyBase64(value string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.RawURLEncoding.Strict(), base64.URLEncoding.Strict(),
		base64.RawStdEncoding.Strict(), base64.StdEncoding.Strict(),
	}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
