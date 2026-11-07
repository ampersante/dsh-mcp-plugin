import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

test("the package declares no dependencies of any kind", () => {
	for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
		const declared = manifest[field];
		assert.ok(!declared || Object.keys(declared).length === 0, `${field} must stay empty, found ${JSON.stringify(declared)}`);
	}
});

test("no lockfile is shipped", () => {
	for (const file of ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "npm-shrinkwrap.json"]) {
		assert.equal(existsSync(join(root, file)), false, `${file} must not exist`);
	}
});

test("tests and runtime reach only builtins and the harness runtime", () => {
	const source = readFileSync(join(root, "oauth.js"), "utf8");
	const imports = [...source.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]);
	for (const specifier of imports) {
		const local = specifier.startsWith("./");
		const builtin = specifier.startsWith("node:");
		const runtime = specifier === "@modelcontextprotocol/client";
		assert.ok(local || builtin || runtime, `unexpected import: ${specifier}`);
	}
});
