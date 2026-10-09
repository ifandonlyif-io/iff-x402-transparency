// Package mldsavectors generates and checks spec/testdata/ml_dsa_65_vectors.json,
// the cross-implementation known-answer file for the ML-DSA-65 primitive and
// for the profile v2 examples (spec/x402-signatures-ml-dsa-65.md).
//
// IFF_UPDATE_VECTORS=1 go test ./internal/mldsavectors  rewrites the file.
// Without it, the test regenerates the file from the checked-in hedged
// signatures (hedged signing is randomized, so those two are inputs, not
// outputs), requires a byte-for-byte match, and verifies every case with
// crypto/mldsa.
package mldsavectors

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const (
	vectorPath = "../../../spec/testdata/ml_dsa_65_vectors.json"
	numKeys    = 6
	omega      = 55
	kHints     = 6
	cTildeLen  = 48
	zLen       = 3200
	hintOff    = cTildeLen + zLen // start of the 61 hint bytes
	sigLen     = 3309
)

type keyEntry struct {
	ID             int    `json:"id"`
	SeedDerivation string `json:"seed_derivation"`
	SeedHex        string `json:"seed_hex"`
	PublicKeyHex   string `json:"public_key_hex"`
}

type caseEntry struct {
	Name         string `json:"name"`
	Key          int    `json:"key"`
	PublicKeyHex string `json:"public_key_hex,omitempty"` // overrides key when set
	MessageHex   string `json:"message_hex"`
	ContextHex   string `json:"context_hex"`
	SignatureHex string `json:"signature_hex"`
	Signing      string `json:"signing"`
	Expected     bool   `json:"expected"`
	Note         string `json:"note"`
}

type sthExample struct {
	Seed         string `json:"test_private_key_seed_base64url"`
	PublicKey    string `json:"public_key_base64"`
	LogID        string `json:"log_id"`
	TreeSize     int    `json:"tree_size"`
	Timestamp    string `json:"timestamp"`
	RootHash     string `json:"root_hash"`
	Canonical    string `json:"canonical_bytes"`
	SHA256       string `json:"sha256_hash"`
	Domain       string `json:"domain"`
	SignedMsgHex string `json:"signed_message_hex"`
	Signature    string `json:"signature_base64"`
	Algorithm    string `json:"signature_algorithm"`
}

type reportExample struct {
	Seed         string `json:"test_private_key_seed_base64url"`
	PublicKey    string `json:"public_key_base64"`
	Canonical    string `json:"canonical_report_json"`
	ReportHash   string `json:"report_hash"`
	Domain       string `json:"domain"`
	SignedMsgHex string `json:"signed_message_hex"`
	Signature    string `json:"signature_base64"`
	Algorithm    string `json:"monitor_signature_algorithm"`
}

type profileExamples struct {
	Description string        `json:"description"`
	Signing     string        `json:"signing"`
	STH         sthExample    `json:"signed_tree_head"`
	Report      reportExample `json:"monitor_report"`
	// NegativeSignatures are valid ML-DSA-65 signatures by the STH key over the
	// wrong message; a profile v2 STH verifier must reject each for the STH.
	NegativeSignatures map[string]string `json:"negative_signatures_for_signed_tree_head"`
}

type vectorFile struct {
	Description string          `json:"description"`
	Warning     string          `json:"test_seed_warning"`
	Algorithm   string          `json:"algorithm"`
	Parameters  map[string]int  `json:"parameters"`
	Keys        []keyEntry      `json:"keys"`
	Cases       []caseEntry     `json:"cases"`
	Profile     profileExamples `json:"profile_v2_examples"`
}

func mustKey(t *testing.T, seed []byte) *mldsa.PrivateKey {
	t.Helper()
	k, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testMessage(n int) []byte {
	m := make([]byte, n)
	for j := range m {
		m[j] = byte((j*31 + n) % 251)
	}
	return m
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

// build generates the whole file. hedged maps case name to a checked-in hedged
// signature; when a name is absent (update mode) a fresh one is produced.
func build(t *testing.T, hedged map[string][]byte) vectorFile {
	t.Helper()
	vf := vectorFile{
		Description: "Known-answer vectors for the ML-DSA-65 verification primitive (FIPS 204, pure mode) and profile v2 examples. Generated and verified by go/internal/mldsavectors with crypto/mldsa, and re-verified by spec/ml_dsa_65.py. Each case states the exact expected verify result.",
		Warning:     "Every seed in this file is public and test-only. Never use any of them as a real key.",
		Algorithm:   "ML-DSA-65",
		Parameters: map[string]int{
			"public_key_bytes": 1952, "signature_bytes": sigLen, "seed_bytes": 32,
			"omega": omega, "k": kHints, "l": 5, "gamma1": 1 << 19, "beta": 196,
		},
	}
	privs := make([]*mldsa.PrivateKey, numKeys)
	for i := 0; i < numKeys; i++ {
		label := fmt.Sprintf("iff-x402 ml-dsa-65 primitive vector %d", i)
		sum := sha256.Sum256([]byte(label))
		privs[i] = mustKey(t, sum[:])
		vf.Keys = append(vf.Keys, keyEntry{
			ID:             i,
			SeedDerivation: fmt.Sprintf("SHA-256(%q); public test-only seed", label),
			SeedHex:        hex.EncodeToString(sum[:]),
			PublicKeyHex:   hex.EncodeToString(privs[i].PublicKey().Bytes()),
		})
	}

	add := func(c caseEntry) { vf.Cases = append(vf.Cases, c) }
	sign := func(k int, msg []byte, ctx string) []byte {
		sig, err := privs[k].SignDeterministic(msg, &mldsa.Options{Context: ctx})
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	pos := func(name string, k int, msg []byte, ctx string, sig []byte, signing, note string) {
		add(caseEntry{Name: name, Key: k, MessageHex: hex.EncodeToString(msg), ContextHex: hex.EncodeToString([]byte(ctx)),
			SignatureHex: hex.EncodeToString(sig), Signing: signing, Expected: true, Note: note})
	}
	neg := func(name string, k int, pk []byte, msg []byte, ctx string, sig []byte, note string) {
		c := caseEntry{Name: name, Key: k, MessageHex: hex.EncodeToString(msg), ContextHex: hex.EncodeToString([]byte(ctx)),
			SignatureHex: hex.EncodeToString(sig), Signing: "n/a", Expected: false, Note: note}
		if pk != nil {
			c.PublicKeyHex = hex.EncodeToString(pk)
		}
		add(c)
	}

	lens := []int{0, 1, 32, 33, 1000}
	for i := 0; i < numKeys; i++ {
		n := lens[i%len(lens)]
		m := testMessage(n)
		pos(fmt.Sprintf("key%d_msg%d_det", i, n), i, m, "", sign(i, m, ""), "deterministic", "empty context")
	}
	for _, n := range lens[1:] { // key 0 also covers the remaining lengths
		m := testMessage(n)
		pos(fmt.Sprintf("key0_msg%d_det", n), 0, m, "", sign(0, m, ""), "deterministic", "empty context")
	}
	{
		m := testMessage(33)
		pos("key1_ctx_det", 1, m, "iff-test-context", sign(1, m, "iff-test-context"), "deterministic", "non-empty context")
		long := string(bytes.Repeat([]byte{'c'}, 255))
		pos("key2_ctx255_det", 2, m, long, sign(2, m, long), "deterministic", "context at the 255-byte maximum")
	}
	for i, name := range []string{"key3_hedged_a", "key4_hedged_b"} {
		m := testMessage(32 + i)
		sig, ok := hedged[name]
		if !ok {
			var err error
			sig, err = privs[3+i].Sign(nil, m, nil)
			if err != nil {
				t.Fatal(err)
			}
		}
		pos(name, 3+i, m, "", sig, "hedged", "randomized signing; the checked-in signature is an input to the byte-for-byte check")
	}

	// Negative cases are all derived from one valid deterministic signature.
	msg := testMessage(33)
	good := sign(0, msg, "")
	pk0 := privs[0].PublicKey().Bytes()
	flip := func(off int, bit byte) []byte {
		s := clone(good)
		s[off] ^= bit
		return s
	}
	// Hint bytes of the valid signature: total = number of hint ones.
	total := int(good[hintOff+omega+kHints-1])
	if total == 0 || total >= omega {
		t.Fatalf("unsuitable hint count %d in base signature", total)
	}

	neg("neg_flip_c_tilde", 0, nil, msg, "", flip(0, 0x01), "one bit flipped in c-tilde")
	neg("neg_flip_c_tilde_last", 0, nil, msg, "", flip(cTildeLen-1, 0x80), "top bit of the last c-tilde byte flipped")
	neg("neg_flip_z_first", 0, nil, msg, "", flip(cTildeLen, 0x01), "one bit flipped in the first z coefficient")
	neg("neg_flip_z_mid", 0, nil, msg, "", flip(cTildeLen+1500, 0x10), "one bit flipped in the middle of z")
	neg("neg_flip_hint_index", 0, nil, msg, "", flip(hintOff, 0x01), "one bit flipped in the first hint index byte")
	neg("neg_flip_hint_count", 0, nil, msg, "", flip(hintOff+omega, 0x01), "one bit flipped in the first hint count byte")

	// More than omega hint ones: last cumulative count = omega+1.
	s := clone(good)
	s[hintOff+omega+kHints-1] = omega + 1
	neg("neg_hint_count_over_omega", 0, nil, msg, "", s, "cumulative hint count 56 exceeds omega=55")

	// Counts that decrease.
	s = clone(good)
	s[hintOff+omega+1], s[hintOff+omega+2] = s[hintOff+omega+2]+1, s[hintOff+omega+1]
	neg("neg_hint_counts_decrease", 0, nil, msg, "", s, "cumulative hint counts are not non-decreasing")

	// Non-increasing indices inside polynomial 0: indices 7,3 (decreasing), then 5,5 (equal).
	for _, c := range []struct {
		name string
		a, b byte
		note string
	}{
		{"neg_hint_indices_decreasing", 7, 3, "hint indices 7,3 in one polynomial are decreasing"},
		{"neg_hint_indices_equal", 5, 5, "hint indices 5,5 in one polynomial are equal"},
	} {
		s = clone(good)
		for i := 0; i < omega; i++ {
			s[hintOff+i] = 0
		}
		s[hintOff], s[hintOff+1] = c.a, c.b
		for i := 0; i < kHints; i++ {
			s[hintOff+omega+i] = 2
		}
		neg(c.name, 0, nil, msg, "", s, c.note)
	}

	// Nonzero padding after the last used hint slot.
	s = clone(good)
	s[hintOff+total] = 1
	neg("neg_hint_nonzero_padding", 0, nil, msg, "", s, "a hint slot past the final count is nonzero")

	// z coefficient with |z| = gamma1 - beta (crafted): field value 196 gives z = 2^19 - 196.
	// 20-bit little-endian field 0 occupies bits 0..19 of z.
	s = clone(good)
	field := uint32(196)
	s[cTildeLen] = byte(field)
	s[cTildeLen+1] = byte(field >> 8)
	s[cTildeLen+2] = (s[cTildeLen+2] & 0xF0) | byte(field>>16)
	neg("neg_z_at_gamma1_minus_beta", 0, nil, msg, "", s, "first z coefficient crafted to exactly gamma1-beta, which fails the norm bound")
	s = clone(good)
	s[cTildeLen], s[cTildeLen+1], s[cTildeLen+2] = 0, 0, (s[cTildeLen+2] & 0xF0)
	neg("neg_z_at_gamma1", 0, nil, msg, "", s, "first z coefficient crafted to gamma1 (field 0), far above the bound")

	neg("neg_wrong_message", 0, nil, testMessage(34), "", good, "message differs from the signed one")
	neg("neg_wrong_context", 0, nil, msg, "x", good, "signed with an empty context, verified with context 'x'")
	{
		c := sign(1, msg, "iff-test-context")
		neg("neg_missing_context", 1, nil, msg, "", c, "signed with a non-empty context, verified with an empty one")
	}
	neg("neg_context_256_bytes", 0, nil, msg, string(bytes.Repeat([]byte{'c'}, 256)), good, "context longer than 255 bytes is rejected")
	neg("neg_wrong_key", 1, nil, msg, "", good, "valid signature of key 0 verified under key 1")
	neg("neg_truncated_public_key", 0, pk0[:len(pk0)-1], msg, "", good, "public key is 1951 bytes")
	neg("neg_extended_public_key", 0, append(clone(pk0), 0), msg, "", good, "public key is 1953 bytes")
	neg("neg_truncated_signature", 0, nil, msg, "", good[:len(good)-1], "signature is 3308 bytes")
	neg("neg_extended_signature", 0, nil, msg, "", append(clone(good), 0), "signature is 3310 bytes")
	neg("neg_empty_signature", 0, nil, msg, "", []byte{}, "empty signature")

	vf.Profile = buildProfile(t)
	return vf
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func buildProfile(t *testing.T) profileExamples {
	t.Helper()
	pe := profileExamples{
		Description: "One signed tree head and one monitor report signed exactly per spec/x402-signatures-ml-dsa-65.md section 4 and 5, with public test-only seeds and deterministic signing.",
		Signing:     "deterministic",
	}
	seq := func(start int) []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(start + i)
		}
		return b
	}
	signMsg := func(k *mldsa.PrivateKey, m []byte) []byte {
		sig, err := k.SignDeterministic(m, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}

	// Signed tree head.
	seed := seq(0x00)
	k := mustKey(t, seed)
	pub := k.PublicKey().Bytes()
	fp := sha256.Sum256(pub)
	logID := hex.EncodeToString(fp[:16])
	root := "c6f684ce14d150072e8237a2d0183d75c6681088c406914e684fb0ba8b6eb8fb"
	ts := "2026-08-29T00:00:00.000000Z"
	canon := fmt.Sprintf(`{"log_id":%q,"tree_size":8,"timestamp":%q,"root_hash":%q}`, logID, ts, root)
	d := sha256.Sum256([]byte(canon))
	domain := "iff-x402-tree-head/v2\n"
	m := append([]byte(domain), d[:]...)
	pe.STH = sthExample{
		Seed: b64u(seed), PublicKey: base64.StdEncoding.EncodeToString(pub), LogID: logID, TreeSize: 8,
		Timestamp: ts, RootHash: root, Canonical: canon, SHA256: hex.EncodeToString(d[:]),
		Domain: domain, SignedMsgHex: hex.EncodeToString(m),
		Signature: base64.StdEncoding.EncodeToString(signMsg(k, m)), Algorithm: "ML-DSA-65",
	}

	// Genuine ML-DSA-65 signatures by the STH key over the wrong message.
	wrongDomain := append([]byte("iff-x402-monitor-report/v2\n"), d[:]...)
	pe.NegativeSignatures = map[string]string{
		"v1_style_digest_only_message": base64.StdEncoding.EncodeToString(signMsg(k, d[:])),
		"wrong_domain_line":            base64.StdEncoding.EncodeToString(signMsg(k, wrongDomain)),
	}

	// Monitor report.
	seed = seq(0x20)
	k = mustKey(t, seed)
	pub = k.PublicKey().Bytes()
	pk64 := base64.StdEncoding.EncodeToString(pub)
	report := `{"endpoint_id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","probe_type":"scheduled","monitor_id":"iff-monitor-1","monitor_version":"3.0.0","monitor_public_key":"` + pk64 +
		`","status_code":402,"reachable":true,"protocol_status":"pass","x402_version":2,"latency_ms":123,"payment_options":[{"scheme":"exact","network":"eip155:8453","asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","amount":"1000000","pay_to":"0x000000000000000000000000000000000000dEaD","max_timeout_seconds":60}],"check_codes":["http_402_observed","x402_v2_valid"],"observed_at":"2026-08-29T12:00:00.123456Z"}`
	d = sha256.Sum256([]byte(report))
	domain = "iff-x402-monitor-report/v2\n"
	m = append([]byte(domain), d[:]...)
	pe.Report = reportExample{
		Seed: b64u(seed), PublicKey: pk64, Canonical: report, ReportHash: hex.EncodeToString(d[:]),
		Domain: domain, SignedMsgHex: hex.EncodeToString(m),
		Signature: base64.StdEncoding.EncodeToString(signMsg(k, m)), Algorithm: "ML-DSA-65",
	}
	return pe
}

func marshal(t *testing.T, vf vectorFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// verifyGo checks a case with crypto/mldsa; ok is false for any rejection,
// including an unparseable key.
func verifyGo(pkBytes, msg []byte, ctx string, sig []byte) bool {
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pkBytes)
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: ctx}) == nil
}

func TestVectors(t *testing.T) {
	path := filepath.FromSlash(vectorPath)
	if os.Getenv("IFF_UPDATE_VECTORS") == "1" {
		out := marshal(t, build(t, nil))
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(out))
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with IFF_UPDATE_VECTORS=1 to generate)", err)
	}
	var loaded vectorFile
	if err := json.Unmarshal(onDisk, &loaded); err != nil {
		t.Fatal(err)
	}

	hedged := map[string][]byte{}
	for _, c := range loaded.Cases {
		if c.Signing == "hedged" {
			sig, err := hex.DecodeString(c.SignatureHex)
			if err != nil {
				t.Fatal(err)
			}
			hedged[c.Name] = sig
		}
	}
	if len(hedged) != 2 {
		t.Fatalf("expected 2 hedged cases, found %d", len(hedged))
	}
	if regenerated := marshal(t, build(t, hedged)); !bytes.Equal(regenerated, onDisk) {
		t.Fatal("checked-in vectors differ from regenerated output (run with IFF_UPDATE_VECTORS=1 and review the diff)")
	}

	if len(loaded.Keys) < 6 {
		t.Fatalf("need at least 6 keys, have %d", len(loaded.Keys))
	}
	keyBytes := func(c caseEntry) []byte {
		if c.PublicKeyHex != "" {
			return mustHex(t, c.PublicKeyHex)
		}
		return mustHex(t, loaded.Keys[c.Key].PublicKeyHex)
	}
	positives, negatives := 0, 0
	for _, c := range loaded.Cases {
		got := verifyGo(keyBytes(c), mustHex(t, c.MessageHex), string(mustHex(t, c.ContextHex)), mustHex(t, c.SignatureHex))
		if got != c.Expected {
			t.Errorf("case %s: crypto/mldsa verify = %v, expected %v", c.Name, got, c.Expected)
		}
		if c.Expected {
			positives++
		} else {
			negatives++
		}
	}
	t.Logf("%d positive and %d negative cases verified", positives, negatives)

	// Profile v2 examples: verify with crypto/mldsa exactly as the spec says.
	p := loaded.Profile
	sthPub, _ := base64.StdEncoding.DecodeString(p.STH.PublicKey)
	sthSig, _ := base64.StdEncoding.DecodeString(p.STH.Signature)
	if !verifyGo(sthPub, mustHex(t, p.STH.SignedMsgHex), "", sthSig) {
		t.Error("profile v2 STH signature does not verify")
	}
	repPub, _ := base64.StdEncoding.DecodeString(p.Report.PublicKey)
	repSig, _ := base64.StdEncoding.DecodeString(p.Report.Signature)
	if !verifyGo(repPub, mustHex(t, p.Report.SignedMsgHex), "", repSig) {
		t.Error("profile v2 monitor report signature does not verify")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
