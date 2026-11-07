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

test("every module reaches only builtins and the harness runtime", async () => {
	const { readdirSync } = await import("node:fs");
	const files = [...readdirSync(root).filter((f) => f.endsWith(".js")), ...readdirSync(join(root, "test")).filter((f) => f.endsWith(".mjs")).map((f) => join("test", f))];
	for (const file of files) {
		const source = readFileSync(join(root, file), "utf8");
		const specifiers = [
			...[...source.matchAll(/from\s+"([^"]+)"/g)].map((m) => m[1]),
			...[...source.matchAll(/import\(\s*"([^"]+)"\s*\)/g)].map((m) => m[1])
		];
		for (const specifier of specifiers) {
			const allowed = specifier.startsWith(".") || specifier.startsWith("node:") || specifier.startsWith("@modelcontextprotocol/client") || specifier.startsWith("@deepseek-ai/");
			assert.ok(allowed, `${file}: unexpected import ${specifier}`);
		}
	}
});
