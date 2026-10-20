import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";
// AJV and its format plugin are already locked dependencies of the SDK's
// MCP dependency. Run `cd ts && npm ci` before this development-only check.
import Ajv2020 from "../ts/node_modules/ajv/dist/2020.js";
import addFormats from "../ts/node_modules/ajv-formats/dist/index.js";

const schema = JSON.parse(await readFile(new URL("../schemas/observed-confirmations-v1.json", import.meta.url)));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);
const caseRoot = new URL("./testdata/observed_confirmations_v1/", import.meta.url);

test("every canonical document vector validates against the body schema", async () => {
  for (const name of await readdir(caseRoot)) {
    const body = JSON.parse(await readFile(new URL(`${name}/body.json`, caseRoot)));
    assert.equal(validate(body), true, `${name}: ${JSON.stringify(validate.errors)}`);
  }
});

test("body schema rejects missing fields, extra fields and invalid episode shape", async () => {
  const base = JSON.parse(await readFile(new URL("single_endpoint_two_episodes/body.json", caseRoot)));
  const mutations = [
    (body) => { delete body.uncounted_late_results; },
    (body) => { body.owner = "private"; },
    (body) => { body.totals.probes = -1; },
    (body) => { body.totals.probes = true; },
    (body) => { body.sealed_at = "2026-10-19T00:10:00Z"; },
    (body) => { body.entries[0].episodes[0].state_key = "AB".repeat(32); },
    (body) => { body.entries[0].episodes[0].set_fingerprint = null; },
    (body) => { body.entries[0].episodes[1].last_valid_at = body.sealed_at; },
  ];
  for (const mutate of mutations) {
    const body = structuredClone(base);
    mutate(body);
    assert.equal(validate(body), false, mutate.toString());
  }
});
