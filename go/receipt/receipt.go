// Package receipt implements the vendor-neutral IFF Service Receipt v1
// envelope. It intentionally depends only on the Go standard library so a
// verifier can be embedded without importing the IFF server or its runtime
// dependencies.
package receipt

import (
	"bytes"
	"crypto/ed25519"
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
)

const (
	// Schema identifies both the signed payload and its detached envelope.
	Schema = "https://ifandonlyif.io/schemas/service-receipt-v1.json"

	Algorithm = "Ed25519"

	// Domain is hashed with the canonical payload before Ed25519 signing. It
	// prevents a signature made for another IFF artifact from being accepted
	// as a service receipt.
	Domain = "iff-service-receipt/v1\n"

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

// Envelope carries canonical payload bytes and a detached Ed25519 signature.
// Payload and all key material use unpadded base64url so the same bytes can be
// copied through URLs, JSON, terminals, and smart-contract tooling unchanged.
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

// ComputeProof reserves the provider-neutral extension point. The base v1
// verifier binds these bytes to the receipt but does not validate a provider's
// proof system; callers must use a matching proof adapter before treating it
// as evidence of a particular execution environment.
type ComputeProof struct {
	Type           string `json:"type"`
	Provider       string `json:"provider"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	ArtifactURI    string `json:"artifact_uri"`
	Verifier       string `json:"verifier"`
}

type Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// Verification separates cryptographic integrity from issuer trust and
// time-based action eligibility. A receipt can remain a valid historical
// signature after ExpiresAt, while no longer being fresh enough for an action.
type Verification struct {
	Payload            Payload `json:"payload"`
	PayloadSHA256      string  `json:"payload_sha256"`
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

// ValidateUniqueJSON rejects malformed JSON and duplicate object keys at any
// depth. Service adapters and CLIs use it before extracting an embedded
// envelope so last-key-wins parsing cannot hide substitutions.
func ValidateUniqueJSON(raw []byte) error {
	return rejectDuplicateJSONKeys(raw)
}

// NewSigner loads an unpadded/padded base64 or base64url Ed25519 seed/private
// key. An empty value creates a disabled signer, which keeps receipt issuance
// opt-in at deployment time.
func NewSigner(encodedPrivateKey string) (*Signer, error) {
	encodedPrivateKey = strings.TrimSpace(encodedPrivateKey)
	if encodedPrivateKey == "" {
		return &Signer{}, nil
	}
	raw, err := decodeAnyBase64(encodedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	var privateKey ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		expanded := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !bytes.Equal(expanded, raw) {
			return nil, errors.New("expanded Ed25519 private key has an inconsistent public half")
		}
		privateKey = append(ed25519.PrivateKey(nil), expanded...)
	default:
		return nil, fmt.Errorf("signing key must decode to %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("derive Ed25519 public key")
	}
	return &Signer{privateKey: privateKey, publicKey: append(ed25519.PublicKey(nil), publicKey...)}, nil
}

func (signer *Signer) Enabled() bool {
	return signer != nil && len(signer.privateKey) == ed25519.PrivateKeySize
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
	receiptID, err := newReceiptID()
	if err != nil {
		return Payload{}, err
	}
	requestHash := RequestHash(requestProjection)
	subjectHash := SubjectHash(subject)
	payload := Payload{
		Schema:           Schema,
		ReceiptID:        receiptID,
		Issuer:           strings.TrimRight(strings.TrimSpace(issuer), "/"),
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
	if err := validatePayload(payload); err != nil {
		return Payload{}, err
	}
	return payload, nil
}

func (signer *Signer) Sign(payload Payload) (Envelope, error) {
	if !signer.Enabled() {
		return Envelope{}, ErrDisabled
	}
	if err := validatePayload(payload); err != nil {
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
	signingDigest := signingDigest(payloadBytes)
	signature := ed25519.Sign(signer.privateKey, signingDigest[:])
	return Envelope{
		Schema:        Schema,
		Payload:       rawBase64URL.EncodeToString(payloadBytes),
		PayloadSHA256: hex.EncodeToString(payloadHash[:]),
		Signature: Signature{
			Algorithm: Algorithm,
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
	if err := rejectDuplicateJSONKeys(raw); err != nil {
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
	if envelope.Schema != Schema {
		return Verification{}, ErrUnsupportedSchema
	}
	if envelope.Signature.Algorithm != Algorithm {
		return Verification{}, fmt.Errorf("%w: unsupported signature algorithm", ErrInvalidEnvelope)
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
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return Verification{}, fmt.Errorf("%w: public_key must be a 32-byte base64url Ed25519 key", ErrInvalidEnvelope)
	}
	keyID := KeyID(publicKey)
	if envelope.Signature.KeyID != keyID {
		return Verification{}, fmt.Errorf("%w: key_id mismatch", ErrInvalidEnvelope)
	}
	signature, err := rawBase64URL.DecodeString(envelope.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Verification{}, fmt.Errorf("%w: value must be a 64-byte base64url Ed25519 signature", ErrInvalidEnvelope)
	}
	digest := signingDigest(payloadBytes)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), digest[:], signature) {
		return Verification{}, ErrInvalidSignature
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
	if err := validatePayload(payload); err != nil {
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

// ValidateNonce applies the portable v1 nonce grammar used by service
// adapters: 1-128 ASCII letters, digits, hyphen, underscore, dot, or colon.
func ValidateNonce(value string) error {
	if !validNonce(value) {
		return fmt.Errorf("nonce must contain 1-128 letters, digits, hyphens, underscores, dots, or colons")
	}
	return nil
}

func KeyID(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// ParsePublicKey accepts padded/unpadded standard or URL-safe base64 and
// returns the one canonical unpadded base64url representation.
func ParsePublicKey(encoded string) (PublicKey, error) {
	raw, err := decodeAnyBase64(strings.TrimSpace(encoded))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return PublicKey{}, errors.New("public key must decode to 32 Ed25519 bytes")
	}
	return PublicKey{
		KeyID:     KeyID(raw),
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
	if rejectDuplicateJSONKeys(verification.Subject) != nil || rejectDuplicateJSONKeys(candidate) != nil {
		return false
	}
	left, err := decodeJSONValue(verification.Subject)
	if err != nil {
		return false
	}
	right, err := decodeJSONValue(candidate)
	return err == nil && reflect.DeepEqual(left, right)
}

func signingDigest(payload []byte) [sha256.Size]byte {
	input := make([]byte, 0, len(Domain)+len(payload))
	input = append(input, Domain...)
	input = append(input, payload...)
	return sha256.Sum256(input)
}

func validatePayload(payload Payload) error {
	if payload.Schema != Schema {
		return ErrUnsupportedSchema
	}
	if !validReceiptID(payload.ReceiptID) {
		return fmt.Errorf("%w: receipt_id is invalid", ErrInvalidPayload)
	}
	if !validIssuer(payload.Issuer) {
		return fmt.Errorf("%w: issuer must be an HTTPS origin", ErrInvalidPayload)
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
	if err != nil || len(subject) == 0 || len(subject) > maxSubjectBytes || !json.Valid(subject) {
		return fmt.Errorf("%w: subject must be bounded base64url JSON", ErrInvalidPayload)
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
	}
	port := parsed.Port()
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
