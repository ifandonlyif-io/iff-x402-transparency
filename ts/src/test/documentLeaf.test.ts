import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { documentLeafHash, DOCUMENT_LEAF_DOMAIN } from "../index.js";
import { repoRootFromImportMetaUrl } from "./repoRoot.js";

interface DocumentLeafVectors {
  leaf_data_prefix: string;
  leaf_data_length: number;
  vectors: {
    name: string;
    document_hash: string;
    leaf_data: string;
    leaf_hash: string;
  }[];
}

const path = join(repoRootFromImportMetaUrl(import.meta.url), "spec", "testdata", "observed_document_leaf_vectors.json");
const vectors = JSON.parse(readFileSync(path, "utf8")) as DocumentLeafVectors;

test("document leaf vectors pin the domain and 62-byte leaf data", () => {
  assert.equal(DOCUMENT_LEAF_DOMAIN, vectors.leaf_data_prefix);
  assert.equal(vectors.leaf_data_length, 62);
  assert.ok(vectors.vectors.length > 0);
});

for (const vector of vectors.vectors) {
  test(`documentLeafHash: ${vector.name}`, async () => {
    assert.match(vector.document_hash, /^[0-9a-f]{64}$/);
    const hash = Buffer.from(vector.document_hash, "hex");
    const before = Buffer.from(hash);
    const leafData = Buffer.concat([Buffer.from(DOCUMENT_LEAF_DOMAIN, "utf8"), hash]);
    assert.equal(leafData.length, vectors.leaf_data_length);
    assert.equal(leafData.toString("hex"), vector.leaf_data);
    const leaf = await documentLeafHash(hash);
    assert.equal(Buffer.from(leaf).toString("hex"), vector.leaf_hash);
    assert.deepEqual(hash, before, "hashing must not mutate the caller's digest");
    const observationLeaf = createHash("sha256").update(Buffer.concat([Buffer.from([0]), hash])).digest("hex");
    assert.notEqual(Buffer.from(leaf).toString("hex"), observationLeaf);
  });
}

test("documentLeafHash rejects non-SHA-256 input lengths", async () => {
  for (const length of [0, 31, 33, 64]) {
    await assert.rejects(documentLeafHash(new Uint8Array(length)), RangeError);
  }
});
