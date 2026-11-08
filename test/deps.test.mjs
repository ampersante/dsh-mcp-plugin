import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

function walk(dir) {
	if (!existsSync(dir)) return [];
	const files = [];
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) files.push(...walk(path));
		else if (entry.isFile() && entry.name.endsWith(".mjs")) files.push(relative(root, path).split(sep).join("/"));
	}
	return files;
}

const files = [
	...readdirSync(root, { withFileTypes: true })
		.filter((entry) => entry.isFile() && entry.name.endsWith(".js"))
		.map((entry) => entry.name),
	...walk(join(root, "test")),
	...walk(join(root, "tools"))
].sort();

const patterns = [
	/from\s+["']([^"']+)["']/g,
	/import\s*\(\s*["']([^"']+)["']\s*\)/g,
	/import\s*["']([^"']+)["']/g
];

function specifiersIn(source) {
	const found = new Set();
	for (const pattern of patterns) {
		for (const match of source.matchAll(pattern)) found.add(match[1]);
	}
	return found;
}

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

test("every module reaches only builtins and the harness runtime", () => {
	for (const file of files) {
		const source = readFileSync(join(root, file), "utf8");
		for (const specifier of specifiersIn(source)) {
			const allowed = specifier.startsWith(".") || specifier.startsWith("node:") || specifier.startsWith("@modelcontextprotocol/client") || specifier.startsWith("@deepseek-ai/");
			assert.ok(allowed, `${file}: unexpected import ${specifier}`);
		}
	}
});
