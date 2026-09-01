import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
    MAX_RECEIPT_INPUT_BYTES,
    RECEIPT_DOMAIN,
    RECEIPT_SCHEMA,
    SUBJECT_HASH_DOMAIN,
    parseJSONStrict,
    verifyServiceReceipt,
} from "./service-receipt.mjs";

const vector = JSON.parse(readFileSync(new URL("../spec/testdata/service_receipt_v1.json", import.meta.url), "utf8"));
const logVector = JSON.parse(readFileSync(new URL("../spec/testdata/log_vectors.json", import.meta.url), "utf8"));
const encoder = new TextEncoder();

function base64URL(bytes) {
    return Buffer.from(bytes).toString("base64url");
}

function validEnvelope() {
    return JSON.parse(JSON.stringify(vector.valid.envelope));
}

async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function signPayloadText(payloadText, domain = RECEIPT_DOMAIN) {
    const seed = Buffer.from(vector.test_private_key_seed_base64, "base64");
    const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
    const key = await crypto.subtle.importKey("pkcs8", Buffer.concat([pkcs8Prefix, seed]), { name: "Ed25519" }, false, ["sign"]);
    const payloadBytes = encoder.encode(payloadText);
    const payloadHash = await sha256(payloadBytes);
    const digest = await sha256(Buffer.concat([Buffer.from(domain), Buffer.from(payloadBytes)]));
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, digest));
    return {
        schema: RECEIPT_SCHEMA,
        payload: base64URL(payloadBytes),
        payload_sha256: Buffer.from(payloadHash).toString("hex"),
        signature: {
            algorithm: "Ed25519",
            key_id: vector.valid.key_id,
            public_key: vector.valid.public_key_base64url,
            value: base64URL(signature),
        },
    };
}

const pinnedOptions = {
    expectedIssuer: vector.valid.trusted_policy.expected_issuer,
    trustedKeyIDs: vector.valid.trusted_policy.trusted_key_ids,
    now: vector.valid.current_time,
};

test("browser verifier reproduces the published baseline vector", async () => {
    const result = await verifyServiceReceipt(JSON.stringify(validEnvelope()), pinnedOptions);
    assert.equal(result.signatureValid, true);
    assert.equal(result.issuerTrust, "trusted");
    assert.equal(result.expired, false);
    assert.equal(result.notYetValid, false);
    assert.equal(result.subjectText, vector.canonical_subject);
    assert.equal(result.evidenceStatus, "absent");
    assert.equal(result.computeProofStatus, "absent");
    assert.equal(result.subjectMatchesOuter, null);
    assert.equal(JSON.stringify(result.envelope), JSON.stringify(vector.valid.envelope));
});

test("issuer pin, same-origin directory, and embedded-only trust remain separate", async () => {
    const envelope = validEnvelope();
    const issuerWithoutPin = await verifyServiceReceipt(JSON.stringify(envelope), {
        now: vector.valid.current_time,
        expectedIssuer: vector.valid.trusted_policy.expected_issuer,
    });
    assert.equal(issuerWithoutPin.signatureValid, true);
    assert.equal(issuerWithoutPin.issuerTrust, "untrusted");

    const pinWithoutIssuer = await verifyServiceReceipt(JSON.stringify(envelope), {
        now: vector.valid.current_time,
        trustedKeyIDs: vector.valid.trusted_policy.trusted_key_ids,
    });
    assert.equal(pinWithoutIssuer.signatureValid, true);
    assert.equal(pinWithoutIssuer.issuerTrust, "untrusted");

    const wrongIssuer = await verifyServiceReceipt(JSON.stringify(envelope), {
        ...pinnedOptions, expectedIssuer: "https://other.example",
    });
    assert.equal(wrongIssuer.issuerTrust, "untrusted");

    const knownDirectory = {
        schema: "https://ifandonlyif.io/schemas/service-receipt-key-directory-v1.json",
        issuer: "https://ifandonlyif.io",
        enabled: true,
        keys: [{
            key_id: vector.valid.key_id, algorithm: "Ed25519",
            public_key: vector.valid.public_key_base64url,
            purpose: "service-receipt-signing", status: "current",
        }],
    };
    const known = await verifyServiceReceipt(JSON.stringify(envelope), { now: vector.valid.current_time, knownDirectory });
    assert.equal(known.issuerTrusted, false);
    assert.equal(known.issuerKnown, true);
    assert.equal(known.issuerTrust, "known");

    const malformedDirectory = { ...knownDirectory, schema: "unexpected" };
    const embeddedOnly = await verifyServiceReceipt(JSON.stringify(envelope), { now: vector.valid.current_time, knownDirectory: malformedDirectory });
    assert.equal(embeddedOnly.issuerTrust, "untrusted");
});

test("full response binding detects outer verdict substitution", async () => {
    const envelope = validEnvelope();
    const subject = JSON.parse(vector.canonical_subject);
    const matching = await verifyServiceReceipt(JSON.stringify({ ...subject, service_receipt: envelope }), pinnedOptions);
    assert.equal(matching.subjectMatchesOuter, true);

    const substituted = await verifyServiceReceipt(JSON.stringify({ ...subject, verdict: "consistent", service_receipt: envelope }), pinnedOptions);
    assert.equal(substituted.signatureValid, true);
    assert.equal(substituted.subject.verdict, "unobserved");
    assert.equal(substituted.subjectMatchesOuter, false);
});

test("tampered payload, signature, and noncanonical base64url fail independently", async () => {
    const payloadTamper = validEnvelope();
    const decoded = Buffer.from(payloadTamper.payload, "base64url").toString("utf8").replace("checkout_7f3a", "checkout_7f3b");
    payloadTamper.payload = Buffer.from(decoded).toString("base64url");
    await assert.rejects(() => verifyServiceReceipt(JSON.stringify(payloadTamper), pinnedOptions), (error) => error.code === "payload_hash_mismatch");

    const signatureTamper = validEnvelope();
    const signature = Buffer.from(signatureTamper.signature.value, "base64url");
    signature[0] ^= 0xff;
    signatureTamper.signature.value = signature.toString("base64url");
    await assert.rejects(() => verifyServiceReceipt(JSON.stringify(signatureTamper), pinnedOptions), (error) => error.code === "signature_mismatch");

    const base64Tamper = validEnvelope();
    base64Tamper.signature.public_key = `${base64Tamper.signature.public_key.slice(0, -1)}h`;
    await assert.rejects(() => verifyServiceReceipt(JSON.stringify(base64Tamper), pinnedOptions), (error) => error.code === "noncanonical_base64url");
});

test("strict JSON rejects duplicates, non-JSON whitespace, and prototype keys safely", async () => {
    const raw = JSON.stringify(validEnvelope());
    const duplicate = raw.replace("{", `{"schema":"${RECEIPT_SCHEMA}",`);
    await assert.rejects(() => verifyServiceReceipt(duplicate, pinnedOptions), (error) => error.code === "duplicate_json_key");
    await assert.rejects(() => verifyServiceReceipt(`\u00a0${raw}`, pinnedOptions), (error) => error.code === "invalid_json");
    const parsed = parseJSONStrict(`{"__proto__":{"polluted":true},"value":1}`);
    assert.equal(parsed.value.value, 1);
    assert.equal({}.polluted, undefined);
});

test("time state is half-open and invalid verifier time is rejected", async () => {
    const envelope = JSON.stringify(validEnvelope());
    const expired = await verifyServiceReceipt(envelope, { ...pinnedOptions, now: "2026-09-01T03:09:05.000Z" });
    assert.equal(expired.signatureValid, true);
    assert.equal(expired.expired, true);
    await assert.rejects(() => verifyServiceReceipt(envelope, { ...pinnedOptions, now: "not-a-time" }), (error) => error.code === "invalid_now");
});

test("negative clock skew is equivalent to zero", async () => {
    const envelope = JSON.stringify(validEnvelope());
    for (const now of ["2026-09-01T03:04:06.000Z", "2026-09-01T03:09:04.000Z"]) {
        const withoutSkew = await verifyServiceReceipt(envelope, { ...pinnedOptions, now, clockSkewMs: 0 });
        const negativeSkew = await verifyServiceReceipt(envelope, { ...pinnedOptions, now, clockSkewMs: -60_000 });
        assert.equal(negativeSkew.expired, withoutSkew.expired);
        assert.equal(negativeSkew.notYetValid, withoutSkew.notYetValid);
    }
});

test("strict JSON container depth accepts 128 and rejects 129 with a controlled error", () => {
    const nestedArray = (depth) => `${"[".repeat(depth)}0${"]".repeat(depth)}`;
    for (const depth of [127, 128]) {
        assert.doesNotThrow(() => parseJSONStrict(nestedArray(depth)));
    }
    assert.throws(
        () => parseJSONStrict(nestedArray(129)),
        (error) => error.code === "json_depth_exceeded" && error.message.includes("128 containers"),
    );
});

test("issuer origin canonicalization matches the Go verifier", async () => {
    for (const issuer of [
        "https://issuer.example",
        "https://issuer.example:8443",
        "https://[2001:db8::1]",
        "https://[2001:db8::1]:8443",
    ]) {
        const payload = JSON.parse(vector.valid.canonical_payload);
        payload.issuer = issuer;
        const envelope = await signPayloadText(JSON.stringify(payload));
        const result = await verifyServiceReceipt(JSON.stringify(envelope), { now: vector.valid.current_time });
        assert.equal(result.signatureValid, true, issuer);
    }
    for (const issuer of [
        "https://ISSUER.example",
        "https://issuer.example:443",
        "https://[2001:0db8:0:0:0:0:0:1]",
        "https://[2001:db8::1]:443",
    ]) {
        const payload = JSON.parse(vector.valid.canonical_payload);
        payload.issuer = issuer;
        const envelope = await signPayloadText(JSON.stringify(payload));
        await assert.rejects(
            () => verifyServiceReceipt(JSON.stringify(envelope), { now: vector.valid.current_time }),
            (error) => error.code === "invalid_payload",
            issuer,
        );
    }
});

test("signed evidence and compute descriptors stay explicitly unverified", async () => {
    const descriptor = vector.evidence_compute;
    const result = await verifyServiceReceipt(JSON.stringify(descriptor.envelope), {
        expectedIssuer: descriptor.trusted_policy.expected_issuer,
        trustedKeyIDs: descriptor.trusted_policy.trusted_key_ids,
        now: descriptor.current_time,
    });
    assert.equal(result.signatureValid, descriptor.expected.signature_valid);
    assert.equal(result.issuerTrusted, descriptor.expected.issuer_trusted);
    assert.equal(result.evidenceStatus, descriptor.expected.evidence_status);
    assert.equal(result.computeProofStatus, descriptor.expected.compute_proof_status);
    assert.equal(result.subjectText, descriptor.canonical_subject);
    assert.equal(result.payload.evidence.log_index, String(logVector.inclusion_proof.log_index));
    const leaf = logVector.leaves[result.payload.evidence.log_index];
    assert.equal(result.payload.evidence.report_hash, leaf.report_hash);
    assert.equal(result.payload.evidence.leaf_hash, leaf.leaf_hash);
    assert.equal(result.payload.evidence.tree_size, String(logVector.tree_size));
    assert.equal(result.payload.evidence.sth_root_hash, logVector.root_hash);
    assert.equal(result.payload.evidence.log_id, logVector.signed_tree_head.log_id);
    assert.equal(result.payload.evidence.sth_sha256_hash, logVector.signed_tree_head.sha256_hash);
});

test("wrong signing domain cannot be replayed as a service receipt", async () => {
    const wrongDomain = await signPayloadText(vector.valid.canonical_payload, "another-protocol/v1\n");
    await assert.rejects(
        () => verifyServiceReceipt(JSON.stringify(wrongDomain), pinnedOptions),
        (error) => error.code === "signature_mismatch",
    );
});

test("signed ambiguous JSON is rejected in payload and subject", async () => {
    const duplicatePayloadText = vector.valid.canonical_payload.replace(
        `"service":"x402-requirement-verification"`,
        `"service":"x402-requirement-verification","service":"x402-requirement-verification"`,
    );
    const duplicatePayload = await signPayloadText(duplicatePayloadText);
    await assert.rejects(
        () => verifyServiceReceipt(JSON.stringify(duplicatePayload), pinnedOptions),
        (error) => error.code === "duplicate_json_key",
    );

    const duplicateSubjectBytes = Buffer.from(`{"value":1,"value":2}`);
    const payload = JSON.parse(vector.valid.canonical_payload);
    payload.subject = duplicateSubjectBytes.toString("base64url");
    payload.subject_sha256 = Buffer.from(await sha256(Buffer.concat([
        Buffer.from(SUBJECT_HASH_DOMAIN), duplicateSubjectBytes,
    ]))).toString("hex");
    const duplicateSubject = await signPayloadText(JSON.stringify(payload));
    await assert.rejects(
        () => verifyServiceReceipt(JSON.stringify(duplicateSubject), pinnedOptions),
        (error) => error.code === "duplicate_json_key",
    );
});

test("evidence decimal and compute URI validation agree with the Go verifier", async () => {
    for (const [name, logIndex, treeSize] of [
        ["leading zero", "05", "8"],
        ["uint64 overflow", "5", "18446744073709551616"],
        ["index outside tree", "8", "8"],
    ]) {
        const payload = JSON.parse(vector.evidence_compute.canonical_payload);
        payload.evidence.log_index = logIndex;
        payload.evidence.tree_size = treeSize;
        const envelope = await signPayloadText(JSON.stringify(payload));
        await assert.rejects(
            () => verifyServiceReceipt(JSON.stringify(envelope), pinnedOptions),
            (error) => error.code === "invalid_evidence",
            name,
        );
    }

    const payload = JSON.parse(vector.evidence_compute.canonical_payload);
    payload.compute_proof = {
        ...payload.compute_proof,
        artifact_uri: "https://user:secret@proofs.example/proof.bin",
    };
    const envelope = await signPayloadText(JSON.stringify(payload));
    await assert.rejects(
        () => verifyServiceReceipt(JSON.stringify(envelope), pinnedOptions),
        (error) => error.code === "invalid_compute_proof",
    );
});

test("semantic payload errors are reported after a valid signature", async () => {
    const nullPayload = await signPayloadText("null");
    await assert.rejects(() => verifyServiceReceipt(JSON.stringify(nullPayload), pinnedOptions), (error) => error.code === "invalid_payload");

    const payload = JSON.parse(vector.valid.canonical_payload);
    payload.subject_sha256 = "00".repeat(32);
    const badSubject = await signPayloadText(JSON.stringify(payload));
    await assert.rejects(() => verifyServiceReceipt(JSON.stringify(badSubject), pinnedOptions), (error) => error.code === "subject_hash_mismatch");

    payload.subject_sha256 = JSON.parse(vector.valid.canonical_payload).subject_sha256;
    payload.issued_at = "2026-02-31T03:04:05.000000Z";
    const badDate = await signPayloadText(JSON.stringify(payload));
    await assert.rejects(() => verifyServiceReceipt(JSON.stringify(badDate), pinnedOptions), (error) => error.code === "invalid_timestamp");
});

test("receipt input byte limit is enforced before parsing", async () => {
    const oversized = " ".repeat(MAX_RECEIPT_INPUT_BYTES + 1);
    await assert.rejects(() => verifyServiceReceipt(oversized), (error) => error.code === "input_size");
});
