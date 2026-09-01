export const RECEIPT_SCHEMA = "https://ifandonlyif.io/schemas/service-receipt-v1.json";
export const RECEIPT_ALGORITHM = "Ed25519";
export const RECEIPT_DOMAIN = "iff-service-receipt/v1\n";
export const REQUEST_HASH_DOMAIN = "iff-service-receipt/request/v1\n";
export const SUBJECT_HASH_DOMAIN = "iff-service-receipt/subject/v1\n";
export const MAX_RECEIPT_INPUT_BYTES = 256 * 1024;

const MAX_PAYLOAD_BYTES = 192 * 1024;
const MAX_SUBJECT_BYTES = 128 * 1024;
const MAX_JSON_DEPTH = 128;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const KEY_ID_PATTERN = /^sha256:[0-9a-f]{64}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const SERVICE_PATTERN = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const META_PATTERN = /^[A-Za-z0-9_.:/@-]{1,128}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export class ReceiptVerificationError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "ReceiptVerificationError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new ReceiptVerificationError(code, message);
}

function own(object, key) {
    return Object.prototype.hasOwnProperty.call(object, key);
}

function requireExactKeys(object, expected, label) {
    if (!object || typeof object !== "object" || Array.isArray(object)) fail("invalid_json_shape", `${label} must be an object.`);
    const actual = Object.keys(object);
    if (actual.length !== expected.length || expected.some((key) => !own(object, key))) {
        fail("unexpected_field", `${label} has missing, unexpected, or misspelled fields.`);
    }
}

// This parser rejects duplicate keys and retains number tokens for exact
// outer/subject comparison beyond JavaScript's safe-integer range.
export function parseJSONStrict(text) {
    if (typeof text !== "string") fail("invalid_json", "Receipt input must be text.");
    let position = 0;
    const whitespace = /[ \t\r\n]/;

    function skipWhitespace() {
        while (position < text.length && whitespace.test(text[position])) position += 1;
    }

    function parseStringNode() {
        const start = position;
        position += 1;
        let escaped = false;
        while (position < text.length) {
            const character = text[position];
            if (!escaped && character === '"') {
                position += 1;
                const raw = text.slice(start, position);
                let value;
                try { value = JSON.parse(raw); } catch { fail("invalid_json", "JSON contains an invalid string escape."); }
                return { kind: "string", value, canonical: JSON.stringify(value) };
            }
            if (!escaped && character.charCodeAt(0) < 0x20) fail("invalid_json", "JSON string contains a control character.");
            if (!escaped && character === "\\") escaped = true;
            else escaped = false;
            position += 1;
        }
        fail("invalid_json", "JSON string is not terminated.");
    }

    function parsePrimitive() {
        const remaining = text.slice(position);
        for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
            if (remaining.startsWith(literal)) {
                position += literal.length;
                return { kind: "primitive", value, canonical: literal };
            }
        }
        const match = remaining.match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
        if (!match) fail("invalid_json", "JSON contains an invalid value.");
        position += match[0].length;
        return { kind: "number", value: Number(match[0]), canonical: match[0] };
    }

    function parseArray(depth) {
        if (depth >= MAX_JSON_DEPTH) fail("json_depth_exceeded", `JSON nesting exceeds ${MAX_JSON_DEPTH} containers.`);
        position += 1;
        const items = [];
        skipWhitespace();
        if (text[position] === "]") {
            position += 1;
            return { kind: "array", value: [], items };
        }
        while (position < text.length) {
            const node = parseValue(depth + 1);
            items.push(node);
            skipWhitespace();
            if (text[position] === "]") {
                position += 1;
                return { kind: "array", value: items.map((item) => item.value), items };
            }
            if (text[position] !== ",") fail("invalid_json", "JSON array is missing a comma.");
            position += 1;
            skipWhitespace();
        }
        fail("invalid_json", "JSON array is not terminated.");
    }

    function parseObject(depth) {
        if (depth >= MAX_JSON_DEPTH) fail("json_depth_exceeded", `JSON nesting exceeds ${MAX_JSON_DEPTH} containers.`);
        position += 1;
        const entries = [];
        const seen = new Set();
        const value = Object.create(null);
        skipWhitespace();
        if (text[position] === "}") {
            position += 1;
            return { kind: "object", value, entries };
        }
        while (position < text.length) {
            if (text[position] !== '"') fail("invalid_json", "JSON object key must be a string.");
            const keyNode = parseStringNode();
            if (seen.has(keyNode.value)) fail("duplicate_json_key", `Duplicate JSON key: ${keyNode.value}`);
            seen.add(keyNode.value);
            skipWhitespace();
            if (text[position] !== ":") fail("invalid_json", "JSON object key is missing a colon.");
            position += 1;
            const node = parseValue(depth + 1);
            entries.push({ key: keyNode.value, node });
            value[keyNode.value] = node.value;
            skipWhitespace();
            if (text[position] === "}") {
                position += 1;
                return { kind: "object", value, entries };
            }
            if (text[position] !== ",") fail("invalid_json", "JSON object is missing a comma.");
            position += 1;
            skipWhitespace();
        }
        fail("invalid_json", "JSON object is not terminated.");
    }

    function parseValue(depth) {
        skipWhitespace();
        const character = text[position];
        if (character === "{") return parseObject(depth);
        if (character === "[") return parseArray(depth);
        if (character === '"') return parseStringNode();
        return parsePrimitive();
    }

    const node = parseValue(0);
    skipWhitespace();
    if (position !== text.length) fail("invalid_json", "Receipt input contains more than one JSON value.");
    return { value: node.value, node };
}

function canonicalNode(node, omitTopLevelKey = "") {
    switch (node.kind) {
    case "object": {
        const entries = node.entries
            .filter(({ key }) => key !== omitTopLevelKey)
            .sort((left, right) => left.key.localeCompare(right.key));
        return `{${entries.map(({ key, node: child }) => `${JSON.stringify(key)}:${canonicalNode(child)}`).join(",")}}`;
    }
    case "array": return `[${node.items.map((item) => canonicalNode(item)).join(",")}]`;
    default: return node.canonical;
    }
}

function bytesToBase64URL(bytes) {
    let binary = "";
    for (let index = 0; index < bytes.length; index += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

export function decodeBase64URL(value, label, expectedLength = null) {
    if (typeof value !== "string" || !BASE64URL_PATTERN.test(value)) fail("invalid_base64url", `${label} must be canonical unpadded base64url.`);
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
    let binary;
    try { binary = atob(padded); } catch { fail("invalid_base64url", `${label} is not valid base64url.`); }
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (bytesToBase64URL(bytes) !== value) fail("noncanonical_base64url", `${label} has non-canonical trailing bits.`);
    if (expectedLength !== null && bytes.length !== expectedLength) fail("invalid_length", `${label} must decode to ${expectedLength} bytes.`);
    return bytes;
}

function concatBytes(...values) {
    const size = values.reduce((total, value) => total + value.length, 0);
    const output = new Uint8Array(size);
    let offset = 0;
    for (const value of values) {
        output.set(value, offset);
        offset += value.length;
    }
    return output;
}

async function sha256(bytes) {
    if (!globalThis.crypto?.subtle) fail("webcrypto_unavailable", "This browser does not provide WebCrypto.");
    return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
}

function hex(bytes) {
    return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function safeCanonicalString(value) {
    return typeof value === "string" && [...value].every((character) => {
        const code = character.charCodeAt(0);
        return code >= 0x20 && code <= 0x7e && !"\\\"<>&".includes(character);
    });
}

function validateIssuer(value) {
    if (!safeCanonicalString(value)) return false;
    let parsed;
    try { parsed = new URL(value); } catch { return false; }
    const localHTTP = parsed.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
    return (parsed.protocol === "https:" || localHTTP) && parsed.origin === value && parsed.username === "" && parsed.password === "";
}

function validateTimestamp(value, label) {
    if (typeof value !== "string" || !TIMESTAMP_PATTERN.test(value) || Number.isNaN(Date.parse(value))) {
        fail("invalid_timestamp", `${label} must be UTC with exactly six fractional digits.`);
    }
    const milliseconds = Date.parse(value);
    if (new Date(milliseconds).toISOString() !== `${value.slice(0, 23)}Z`) {
        fail("invalid_timestamp", `${label} is not a real canonical UTC date.`);
    }
    return milliseconds;
}

function parseCanonicalUint64(value, label) {
    if (typeof value !== "string" || !/^(0|[1-9]\d{0,19})$/.test(value)) fail("invalid_evidence", `${label} is not a canonical uint64.`);
    const parsed = BigInt(value);
    if (parsed > 18446744073709551615n) fail("invalid_evidence", `${label} exceeds uint64.`);
    return parsed;
}

function validatePayloadShape(payload, subjectBytes) {
    const fields = ["schema", "receipt_id", "issuer", "service", "issued_at", "expires_at", "nonce", "request_sha256", "subject_media_type", "subject_sha256", "subject", "evidence", "compute_proof"];
    requireExactKeys(payload, fields, "payload");
    if (payload.schema !== RECEIPT_SCHEMA) fail("unsupported_schema", "The signed payload schema is not supported.");
    if (!/^sr1_[A-Za-z0-9_-]{24}$/.test(payload.receipt_id)) fail("invalid_payload", "receipt_id is invalid.");
    if (!validateIssuer(payload.issuer)) fail("invalid_payload", "issuer must be an HTTPS origin.");
    if (!SERVICE_PATTERN.test(payload.service)) fail("invalid_payload", "service is invalid.");
    const issuedAt = validateTimestamp(payload.issued_at, "issued_at");
    const expiresAt = validateTimestamp(payload.expires_at, "expires_at");
    if (expiresAt <= issuedAt) fail("invalid_payload", "expires_at must be later than issued_at.");
    if (payload.nonce !== null && (typeof payload.nonce !== "string" || !NONCE_PATTERN.test(payload.nonce))) fail("invalid_payload", "nonce is invalid.");
    if (!DIGEST_PATTERN.test(payload.request_sha256) || !DIGEST_PATTERN.test(payload.subject_sha256)) fail("invalid_payload", "Receipt hashes must be lowercase SHA-256 hex.");
    if (payload.subject_media_type !== "application/json") fail("invalid_payload", "subject_media_type is unsupported.");
    if (subjectBytes.length === 0 || subjectBytes.length > MAX_SUBJECT_BYTES) fail("invalid_payload", "Signed subject size is invalid.");
    if (payload.evidence !== null) {
        const evidenceFields = ["observation_id", "report_hash", "leaf_hash", "log_id", "log_index", "tree_size", "sth_root_hash", "sth_sha256_hash"];
        requireExactKeys(payload.evidence, evidenceFields, "evidence");
        const logIndex = parseCanonicalUint64(payload.evidence.log_index, "log_index");
        const treeSize = parseCanonicalUint64(payload.evidence.tree_size, "tree_size");
        if (!UUID_PATTERN.test(payload.evidence.observation_id) || !/^[0-9a-f]{32}$/.test(payload.evidence.log_id) ||
            ![payload.evidence.report_hash, payload.evidence.leaf_hash, payload.evidence.sth_root_hash, payload.evidence.sth_sha256_hash].every((value) => DIGEST_PATTERN.test(value)) ||
            treeSize === 0n || treeSize <= logIndex) fail("invalid_evidence", "Evidence descriptor is invalid.");
    }
    if (payload.compute_proof !== null) {
        requireExactKeys(payload.compute_proof, ["type", "provider", "artifact_sha256", "artifact_uri", "verifier"], "compute_proof");
        if (!META_PATTERN.test(payload.compute_proof.type) || !META_PATTERN.test(payload.compute_proof.provider) ||
            !DIGEST_PATTERN.test(payload.compute_proof.artifact_sha256) || !META_PATTERN.test(payload.compute_proof.verifier)) fail("invalid_compute_proof", "Compute proof descriptor is invalid.");
        if (payload.compute_proof.artifact_uri !== "") {
            let artifact;
            try { artifact = new URL(payload.compute_proof.artifact_uri); } catch { fail("invalid_compute_proof", "Compute artifact URI is invalid."); }
            if (artifact.protocol !== "https:" || artifact.username !== "" || artifact.password !== "" ||
                !safeCanonicalString(payload.compute_proof.artifact_uri)) fail("invalid_compute_proof", "Compute artifact URI must use HTTPS without credentials.");
        }
    }
    return { issuedAt, expiresAt };
}

function normalizeNow(value) {
    let result;
    if (value instanceof Date) result = value.getTime();
    else if (typeof value === "string") result = Date.parse(value);
    else if (typeof value === "number") result = value;
    else result = Date.now();
    if (!Number.isFinite(result)) fail("invalid_now", "Verifier time is invalid.");
    return result;
}

function directoryRecognizes(directory, issuer, keyID, publicKey) {
    if (!directory || typeof directory !== "object" || Array.isArray(directory)) return false;
    try {
        requireExactKeys(directory, ["schema", "issuer", "enabled", "keys"], "key directory");
        if (directory.schema !== "https://ifandonlyif.io/schemas/service-receipt-key-directory-v1.json" ||
            directory.issuer !== issuer || typeof directory.enabled !== "boolean" || !Array.isArray(directory.keys)) return false;
        return directory.keys.some((key) => {
            requireExactKeys(key, ["key_id", "algorithm", "public_key", "purpose", "status"], "directory key");
            return key.key_id === keyID && key.public_key === publicKey && key.algorithm === RECEIPT_ALGORITHM &&
                key.purpose === "service-receipt-signing" && ["current", "previous", "inactive"].includes(key.status);
        });
    } catch {
        return false;
    }
}

export async function verifyServiceReceipt(inputText, options = {}) {
    const inputBytes = textEncoder.encode(inputText);
    if (inputBytes.length === 0 || inputBytes.length > MAX_RECEIPT_INPUT_BYTES) fail("input_size", `Receipt input must be 1-${MAX_RECEIPT_INPUT_BYTES} UTF-8 bytes.`);
    const document = parseJSONStrict(inputText);
    if (document.node.kind !== "object") fail("invalid_json_shape", "Receipt input must be a JSON object.");

    const embedded = own(document.value, "service_receipt");
    const envelope = embedded ? document.value.service_receipt : document.value;
    requireExactKeys(envelope, ["schema", "payload", "payload_sha256", "signature"], "envelope");
    requireExactKeys(envelope.signature, ["algorithm", "key_id", "public_key", "value"], "signature");
    if (envelope.schema !== RECEIPT_SCHEMA) fail("unsupported_schema", "The receipt envelope schema is not supported.");
    if (envelope.signature.algorithm !== RECEIPT_ALGORITHM) fail("unsupported_algorithm", "Only Ed25519 Service Receipt v1 signatures are supported.");
    if (!DIGEST_PATTERN.test(envelope.payload_sha256) || !KEY_ID_PATTERN.test(envelope.signature.key_id)) fail("invalid_envelope", "Envelope hashes are malformed.");

    const payloadBytes = decodeBase64URL(envelope.payload, "payload");
    if (payloadBytes.length === 0 || payloadBytes.length > MAX_PAYLOAD_BYTES) fail("payload_size", "Decoded receipt payload size is invalid.");
    const payloadHash = await sha256(payloadBytes);
    if (hex(payloadHash) !== envelope.payload_sha256) fail("payload_hash_mismatch", "payload_sha256 does not match the signed payload bytes.");
    const publicKey = decodeBase64URL(envelope.signature.public_key, "public_key", 32);
    const signature = decodeBase64URL(envelope.signature.value, "signature", 64);
    const keyID = `sha256:${hex(await sha256(publicKey))}`;
    if (keyID !== envelope.signature.key_id) fail("key_id_mismatch", "key_id does not match the embedded public key.");
    const signingDigest = await sha256(concatBytes(textEncoder.encode(RECEIPT_DOMAIN), payloadBytes));
    let signingKey;
    try {
        signingKey = await globalThis.crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    } catch {
        fail("ed25519_unavailable", "This browser cannot import Ed25519 verification keys.");
    }
    if (!await globalThis.crypto.subtle.verify({ name: "Ed25519" }, signingKey, signature, signingDigest)) {
        fail("signature_mismatch", "Receipt contents and signature do not match.");
    }

    let payloadText;
    try { payloadText = textDecoder.decode(payloadBytes); } catch { fail("invalid_payload", "Payload is not valid UTF-8."); }
    const payloadDocument = parseJSONStrict(payloadText);
    if (payloadDocument.node.kind !== "object") fail("invalid_payload", "Signed payload must be a JSON object.");
    const payload = payloadDocument.value;
    if (JSON.stringify(payload) !== payloadText) fail("noncanonical_payload", "Signed payload is not canonical fixed-order JSON.");
    const subjectBytes = decodeBase64URL(payload.subject, "subject");
    const time = validatePayloadShape(payload, subjectBytes);
    if (hex(await sha256(concatBytes(textEncoder.encode(SUBJECT_HASH_DOMAIN), subjectBytes))) !== payload.subject_sha256) {
        fail("subject_hash_mismatch", "subject_sha256 does not match the signed result bytes.");
    }
    let subjectText;
    try { subjectText = textDecoder.decode(subjectBytes); } catch { fail("invalid_subject", "Signed subject is not valid UTF-8."); }
    const subjectDocument = parseJSONStrict(subjectText);
    if (subjectDocument.node.kind !== "object") fail("invalid_subject", "Signed subject must be a JSON object.");
    if (payload.evidence !== null) {
        const reportBytes = Uint8Array.from(payload.evidence.report_hash.match(/../g), (value) => Number.parseInt(value, 16));
        const expectedLeaf = hex(await sha256(concatBytes(Uint8Array.of(0), reportBytes)));
        if (expectedLeaf !== payload.evidence.leaf_hash) fail("evidence_leaf_mismatch", "Evidence leaf_hash does not bind report_hash.");
    }

    const expectedIssuer = typeof options.expectedIssuer === "string" ? options.expectedIssuer : "";
    const trustedKeyIDs = new Set(Array.isArray(options.trustedKeyIDs) ? options.trustedKeyIDs : []);
    const issuerTrusted = expectedIssuer !== "" && payload.issuer === expectedIssuer && trustedKeyIDs.has(keyID);
    const issuerKnown = directoryRecognizes(options.knownDirectory, payload.issuer, keyID, envelope.signature.public_key);
    const now = normalizeNow(options.now);
    const skew = Number.isFinite(options.clockSkewMs) && options.clockSkewMs >= 0 ? options.clockSkewMs : 0;
    const expired = now >= time.expiresAt + skew;
    const notYetValid = now + skew < time.issuedAt;
    const subjectMatchesOuter = embedded
        ? canonicalNode(document.node, "service_receipt") === canonicalNode(subjectDocument.node)
        : null;

    return {
        signatureValid: true,
        issuerTrusted,
        issuerKnown,
        issuerTrust: issuerTrusted ? "trusted" : issuerKnown ? "known" : "untrusted",
        expired,
        notYetValid,
        subjectMatchesOuter,
        evidenceStatus: payload.evidence === null ? "absent" : "referenced_unverified",
        computeProofStatus: payload.compute_proof === null ? "absent" : "descriptor_signed_unverified",
        payload,
        subject: subjectDocument.value,
        subjectText,
        envelope,
        keyID,
        payloadSHA256: envelope.payload_sha256,
    };
}
