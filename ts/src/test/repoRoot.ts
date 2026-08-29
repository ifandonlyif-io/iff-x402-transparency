import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Walks up from this file's location until it finds the public conformance
 * vectors, rather than hardcoding a relative depth that would silently
 * break if the compiled test output's directory depth ever changes.
 */
export function findRepoRoot(startDir: string): string {
  let dir = startDir;
  for (let i = 0; i < 20; i++) {
    if (existsSync(join(dir, "spec", "testdata", "fingerprint_vectors.json"))) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }
  throw new Error(`could not find public spec/testdata walking up from ${startDir}`);
}

export function repoRootFromImportMetaUrl(importMetaUrl: string): string {
  return findRepoRoot(dirname(fileURLToPath(importMetaUrl)));
}
