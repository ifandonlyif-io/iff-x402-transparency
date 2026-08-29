// Package preflight is the canonical, independently publishable Go
// implementation of IFF's x402 requirement fingerprint and preflight API.
// The private monitor imports this module for production fingerprinting, so
// the publicly reviewed algorithm and the deployed algorithm do not drift.
//
// The full protocol this client wraps -- the fingerprint algorithm, the
// Merkle transparency log, signed tree heads, and inclusion/consistency
// proofs -- is specified in ../spec/x402-requirement-transparency-v1.md,
// written so a third party can implement a compatible verifier without
// reading this SDK's source. ../spec/verify_example.py is a dependency-light,
// runnable reference verifier that checks a
// live log directly against that spec, independent of this SDK.
//
// This module's canonical, public home is
// https://github.com/ifandonlyif-io/iff-x402-transparency. During extraction
// the private monitor uses a local replace directive; after the first public
// tag it will depend on that immutable tagged version instead.
package preflight

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// FingerprintVersion is the current C1 requirement-fingerprint version.
const FingerprintVersion = 1

const (
	optionFingerprintDomain = "iff-x402-option/v1\n"
	setFingerprintDomain    = "iff-x402-set/v1\n"
	payeeFingerprintDomain  = "iff-x402-payee/v1\n"
)

// evmAddressPattern matches a lowercase-or-mixed-case 20-byte hex address.
// Only values matching this pattern are safe to lowercase; base58 addresses
// (Solana and others) are case-sensitive and must pass through unchanged.
var evmAddressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// PaymentOption is the x402 v2 payment option shape this SDK fingerprints:
// the same safe subset the public v3 evidence API carries.
type PaymentOption struct {
	Scheme            string `json:"scheme"`
	Network           string `json:"network"`
	Asset             string `json:"asset"`
	Amount            string `json:"amount"`
	PayTo             string `json:"pay_to"`
	MaxTimeoutSeconds int    `json:"max_timeout_seconds"`
}

// Fingerprint identifies a normalized payment-option set.
type Fingerprint struct {
	Version   int
	SetFP     string
	OptionFPs []string
}

// PayeeFingerprint is C4 rule 4b's amount-blind payment identity.
type PayeeFingerprint struct {
	Version    int
	PayeeSetFP string
	PayeeFPs   []string
}

type canonicalPaymentOption struct {
	Scheme  string `json:"scheme"`
	Network string `json:"network"`
	Asset   string `json:"asset"`
	PayTo   string `json:"pay_to"`
	Amount  string `json:"amount"`
}

type canonicalPayeeOption struct {
	Scheme  string `json:"scheme"`
	Network string `json:"network"`
	Asset   string `json:"asset"`
	PayTo   string `json:"pay_to"`
}

// ComputeFingerprint derives the C1 requirement fingerprint for a set of
// x402 payment options. ok is false when options is empty.
func ComputeFingerprint(options []PaymentOption) (Fingerprint, bool) {
	if len(options) == 0 {
		return Fingerprint{}, false
	}
	seen := make(map[string]struct{}, len(options))
	optionFPs := make([]string, 0, len(options))
	for _, option := range options {
		fp := computeOptionFingerprint(option)
		if _, duplicate := seen[fp]; duplicate {
			continue
		}
		seen[fp] = struct{}{}
		optionFPs = append(optionFPs, fp)
	}
	sort.Strings(optionFPs)
	return Fingerprint{
		Version:   FingerprintVersion,
		SetFP:     computeSetFingerprint(optionFPs),
		OptionFPs: optionFPs,
	}, true
}

// ComputePayeeFingerprint derives C4 rule 4b's amount-blind payee
// fingerprint: the same options as ComputeFingerprint, hashed without the
// amount field, so two option sets that differ only in price share a
// PayeeSetFP. ok is false when options is empty.
func ComputePayeeFingerprint(options []PaymentOption) (PayeeFingerprint, bool) {
	if len(options) == 0 {
		return PayeeFingerprint{}, false
	}
	seen := make(map[string]struct{}, len(options))
	payeeFPs := make([]string, 0, len(options))
	for _, option := range options {
		fp := computePayeeOptionFingerprint(option)
		if _, duplicate := seen[fp]; duplicate {
			continue
		}
		seen[fp] = struct{}{}
		payeeFPs = append(payeeFPs, fp)
	}
	sort.Strings(payeeFPs)
	return PayeeFingerprint{
		Version:    FingerprintVersion,
		PayeeSetFP: computeSetFingerprint(payeeFPs),
		PayeeFPs:   payeeFPs,
	}, true
}

func computeOptionFingerprint(option PaymentOption) string {
	canonical := canonicalPaymentOption{
		Scheme:  strings.ToLower(strings.TrimSpace(option.Scheme)),
		Network: strings.ToLower(strings.TrimSpace(option.Network)),
		Asset:   NormalizeAddressLikeField(option.Asset),
		PayTo:   NormalizeAddressLikeField(option.PayTo),
		Amount:  NormalizeAmount(option.Amount),
	}
	return domainSeparatedHash(optionFingerprintDomain, marshalCanonicalJSON(canonical))
}

func computePayeeOptionFingerprint(option PaymentOption) string {
	canonical := canonicalPayeeOption{
		Scheme:  strings.ToLower(strings.TrimSpace(option.Scheme)),
		Network: strings.ToLower(strings.TrimSpace(option.Network)),
		Asset:   NormalizeAddressLikeField(option.Asset),
		PayTo:   NormalizeAddressLikeField(option.PayTo),
	}
	return domainSeparatedHash(payeeFingerprintDomain, marshalCanonicalJSON(canonical))
}

func computeSetFingerprint(sortedUniqueFPs []string) string {
	hasher := sha256.New()
	hasher.Write([]byte(setFingerprintDomain))
	hasher.Write([]byte(strings.Join(sortedUniqueFPs, "\n")))
	return hex.EncodeToString(hasher.Sum(nil))
}

func domainSeparatedHash(domain string, payload []byte) string {
	hasher := sha256.New()
	hasher.Write([]byte(domain))
	hasher.Write(payload)
	return hex.EncodeToString(hasher.Sum(nil))
}

// NormalizeAddressLikeField implements the C1 asset/pay_to rule: an
// EVM-style 0x address is lowercased; anything else (in particular a
// case-sensitive base58 address) is only trimmed.
func NormalizeAddressLikeField(value string) string {
	trimmed := strings.TrimSpace(value)
	if evmAddressPattern.MatchString(trimmed) {
		return strings.ToLower(trimmed)
	}
	return trimmed
}

// NormalizeAmount implements the C1 amount rule: trim, then strip leading
// zeros only when the trimmed value is purely ASCII decimal digits.
func NormalizeAmount(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return trimmed
	}
	for _, r := range trimmed {
		if r < '0' || r > '9' {
			return trimmed
		}
	}
	stripped := strings.TrimLeft(trimmed, "0")
	if stripped == "" {
		return "0"
	}
	return stripped
}

// marshalCanonicalJSON produces compact, HTML-unescaped JSON, matching C1's
// contract (encoding/json.Marshal always HTML-escapes '<'/'>'/'&', which C1
// forbids).
func marshalCanonicalJSON(value interface{}) []byte {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return bytes.TrimRight(buf.Bytes(), "\n")
}
