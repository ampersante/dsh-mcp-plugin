/**
 * The MCP SDK that ships inside the DeepSeek Harness application bundle.
 *
 * The plugin imports `@modelcontextprotocol/client` by bare name, so a test of
 * the real contract must provide the very same build the application runs.
 * This module reads the package (and its runtime dependencies) out of
 * `app.asar` into a fresh temporary `node_modules` and redirects that one
 * specifier to the extracted copy.
 *
 * The bundle layout is version-specific: when it changes, the test fails with
 * the message below instead of silently skipping.
 */
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after } from "node:test";
import { pathToFileURL } from "node:url";

export const DEFAULT_ASAR = "/Applications/DeepSeek Harness.app/Contents/Resources/app.asar";
export const SDK_PACKAGE = "@modelcontextprotocol/client";

const SDK_ENTRY = "dist/index.mjs";
const PACKAGE_ROOT = "dsh/node_modules/";
const MAX_HEADER_BYTES = 64 * 1024 * 1024;

/** Overridable so the skip and failure paths can be exercised without moving the bundle. */
export const ASAR = process.env.DSH_MCP_OAUTH_ASAR ?? DEFAULT_ASAR;

function bundleError(cause) {
	return new Error(
		`${SDK_PACKAGE}: the DeepSeek Harness bundle at ${ASAR} could not be read or loaded (${cause instanceof Error ? cause.message : String(cause)}); ` +
			"update test/support/sdk.mjs for this harness version",
		{ cause }
	);
}

/**
 * Reads the asar header and returns the file tree plus the offset where file
 * data begins.
 *
 * Layout: [0,4) marker, [4,8) headerSize; the header block starts at 8, its
 * first 8 bytes are the payload size and the JSON length, so the JSON starts
 * at file offset 16 and file data at 8 + headerSize.
 */
function readAsar(asar) {
	const size = statSync(asar).size;
	const fd = openSync(asar, "r");
	try {
		const head = Buffer.alloc(16);
		if (readSync(fd, head, 0, head.length, 0) !== head.length) throw new Error("the file is too short to hold an asar header");
		const headerSize = head.readUInt32LE(4);
		if (headerSize < 8 || headerSize > size - 8 || headerSize > MAX_HEADER_BYTES) {
			throw new Error(`implausible asar header size ${headerSize} for a ${size}-byte file`);
		}
		const block = Buffer.alloc(headerSize);
		if (readSync(fd, block, 0, block.length, 8) !== block.length) throw new Error("the asar header block is truncated");
		const stringLength = block.readUInt32LE(4);
		if (stringLength === 0 || 8 + stringLength > headerSize) {
			throw new Error(`implausible asar header string length ${stringLength}`);
		}
		const tree = JSON.parse(block.subarray(8, 8 + stringLength).toString("utf8"));
		return { tree, dataOffset: 8 + headerSize };
	} finally {
		closeSync(fd);
	}
}

function lookup(tree, path) {
	let node = tree;
	for (const part of path.split("/")) {
		if (!part) continue;
		node = node.files?.[part];
		if (!node) return undefined;
	}
	return node;
}

/** Reads one archived file by its tree entry. */
function readEntry(fd, dataOffset, entry) {
	const size = Number(entry.size);
	const buffer = Buffer.alloc(size);
	if (readSync(fd, buffer, 0, size, dataOffset + Number(entry.offset)) !== size) {
		throw new Error("an archived file is truncated");
	}
	return buffer;
}

function packageJson(fd, dataOffset, tree, name) {
	const entry = lookup(tree, `${PACKAGE_ROOT}${name}/package.json`);
	if (!entry || entry.files) return undefined;
	return JSON.parse(readEntry(fd, dataOffset, entry).toString("utf8"));
}

/** Walks the dependency closure. A dependency the bundle does not carry is not fatal. */
function resolveClosure(fd, dataOffset, tree) {
	const closure = new Map();
	const queue = [SDK_PACKAGE];
	while (queue.length > 0) {
		const name = queue.shift();
		if (closure.has(name)) continue;
		const manifest = packageJson(fd, dataOffset, tree, name);
		if (!manifest) {
			if (name === SDK_PACKAGE) throw new Error(`${PACKAGE_ROOT}${name} is absent from the bundle`);
			continue;
		}
		closure.set(name, manifest.version);
		for (const dependency of Object.keys(manifest.dependencies ?? {})) queue.push(dependency);
	}
	return closure;
}

function walkFiles(node, prefix, out) {
	if (node.files) {
		for (const [name, child] of Object.entries(node.files)) walkFiles(child, `${prefix}/${name}`, out);
		return out;
	}
	if (node.size === undefined) return out;
	if (node.unpacked) throw new Error(`${prefix} is stored outside the archive`);
	out.push({ path: prefix, entry: node });
	return out;
}

/** Extracts the SDK closure into `<dest>/node_modules/...` — the component Node needs. */
function extract(asar, dest) {
	const { tree, dataOffset } = readAsar(asar);
	const fd = openSync(asar, "r");
	try {
		const closure = resolveClosure(fd, dataOffset, tree);
		const directories = new Set();
		let count = 0;
		for (const name of closure.keys()) {
			const node = lookup(tree, `${PACKAGE_ROOT}${name}`);
			if (!node || node.files === undefined) continue;
			for (const file of walkFiles(node, name, [])) {
				const target = join(dest, "node_modules", ...file.path.split("/"));
				const directory = dirname(target);
				if (!directories.has(directory)) {
					mkdirSync(directory, { recursive: true });
					directories.add(directory);
				}
				writeFileSync(target, readEntry(fd, dataOffset, file.entry));
				count += 1;
			}
		}
		const entry = join(dest, "node_modules", ...SDK_PACKAGE.split("/"), ...SDK_ENTRY.split("/"));
		if (!existsSync(entry)) throw new Error(`${PACKAGE_ROOT}${SDK_PACKAGE}/${SDK_ENTRY} is absent from the bundle`);
		return { packages: closure.size, files: count, entry };
	} finally {
		closeSync(fd);
	}
}

/**
 * Extracts the bundled SDK into a fresh temporary tree and imports it.
 *
 * Returns `null` only when the bundle is not installed (the test skips with a
 * reason). Every other failure throws, naming the bundle: a harness update
 * that changes the layout must not turn the test green by skipping it.
 */
export async function resolveSdk() {
	let stats;
	try {
		stats = statSync(ASAR);
	} catch (error) {
		if (error?.code === "ENOENT") return null;
		throw bundleError(error);
	}
	if (!stats.isFile()) throw bundleError(new Error("the path is not a regular file"));

	let dest;
	try {
		dest = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-sdk-"));
		after(() => rmSync(dest, { recursive: true, force: true }));
		const { entry } = extract(ASAR, dest);
		const url = pathToFileURL(entry).href;
		await import(url);
		return { url };
	} catch (error) {
		if (dest) rmSync(dest, { recursive: true, force: true });
		throw bundleError(error);
	}
}

/**
 * Makes `import "@modelcontextprotocol/client"` resolve to the extracted copy.
 *
 * Must run before `oauth.js` is imported; `registerHooks` is loaded lazily so
 * this module itself still loads on an older Node.
 */
export async function installResolveHook(url) {
	const { registerHooks } = await import("node:module");
	if (typeof registerHooks !== "function") {
		throw new Error(`node:module has no registerHooks in Node ${process.version}; Node 22.15+ or 24 is required to load the harness SDK`);
	}
	registerHooks({
		resolve(specifier, context, nextResolve) {
			if (specifier === SDK_PACKAGE) return { url, shortCircuit: true };
			return nextResolve(specifier, context);
		}
	});
}
