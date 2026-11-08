/**
 * A stand-in for the macOS `security` tool, so the Keychain store in
 * `oauth.js` is exercised without reading or writing the real Keychain.
 *
 * `oauth.js` spawns the bare name `security`, so the stub must sit in PATH.
 * A shebang carrying the embedded Node path cannot work here: the path holds
 * spaces and the kernel splits the interpreter line at the first one. The
 * shell wrapper therefore execs Node with the path quoted, and locates its
 * own directory with `${0%/*}` instead of `dirname` (an external command,
 * unavailable once the test replaces PATH).
 *
 * The store is a JSON file next to the wrapper, keyed by `<service>/<account>`
 * and holding the base64 value exactly as `security` would print it.
 */
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const STUB_SOURCE = String.raw`import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const storePath = join(here, "store.json");

function refuse(message) {
	process.stderr.write("stub security: " + message + "\n");
	process.exitCode = 1;
	throw new Error("stub security: " + message);
}

if (existsSync(join(here, "fail"))) refuse("forced failure");

function readStore() {
	try {
		const parsed = JSON.parse(readFileSync(storePath, "utf8"));
		return parsed && typeof parsed === "object" ? parsed : {};
	} catch {
		return {};
	}
}

function writeStore(store) {
	writeFileSync(storePath, JSON.stringify(store) + "\n");
}

function valueOf(args, flag) {
	const index = args.indexOf(flag);
	if (index < 0 || index + 1 >= args.length) refuse("missing " + flag);
	return args[index + 1];
}

const args = process.argv.slice(2);
const command = args[0];

if (command === "find-generic-password") {
	const key = valueOf(args, "-s") + "/" + valueOf(args, "-a");
	const store = readStore();
	if (!Object.hasOwn(store, key)) {
		process.stderr.write("security: The specified item could not be found in the keychain.\n");
		process.exitCode = 44;
	} else {
		process.stdout.write(store[key] + "\n");
	}
} else if (command === "delete-generic-password") {
	const key = valueOf(args, "-s") + "/" + valueOf(args, "-a");
	const store = readStore();
	delete store[key];
	writeStore(store);
} else if (command === "-i") {
	let input = "";
	for await (const chunk of process.stdin) input += chunk;
	const store = readStore();
	// The real security -i reads stdin line by line and silently truncates a
	// line past 4096 characters, still exiting 0. Reproduce that before parsing.
	for (const line of input.split("\n")) {
		if (!line.trim()) continue;
		const words = line.slice(0, 4096).trim().split(/\s+/);
		if (words[0] !== "add-generic-password") refuse("unsupported stdin command: " + words[0]);
		const key = valueOf(words, "-s") + "/" + valueOf(words, "-a");
		store[key] = valueOf(words, "-w");
	}
	writeStore(store);
} else {
	refuse("unsupported invocation: " + args.join(" "));
}
`;

/** Quote a value for POSIX sh, keeping spaces and other metacharacters intact. */
function shellQuote(value) {
	return '"' + value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\$/g, "\\$").replace(/`/g, "\\`") + '"';
}

/**
 * Read the stub's JSON store. A missing or unreadable file means no records,
 * which is exactly what a test needs to prove that a delete really happened.
 */
export function readStubStore(storePath) {
	try {
		const parsed = JSON.parse(readFileSync(storePath, "utf8"));
		return parsed && typeof parsed === "object" ? parsed : {};
	} catch {
		return {};
	}
}

/**
 * Install the stub for one test and restore PATH afterwards.
 *
 * `fail: true` makes every invocation exit 1 with a message on stderr, which
 * drives `oauth.js` onto its file fallback. `hard: true` leaves only the stub
 * directory in PATH, so a missed stub cannot silently reach the real Keychain.
 */
export function installSecurityStub(t, { fail = false, hard = false } = {}) {
	const dir = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-security-"));
	const wrapperPath = join(dir, "security");
	const storePath = join(dir, "store.json");
	writeFileSync(join(dir, "security.mjs"), STUB_SOURCE, { mode: 0o644 });
	writeFileSync(wrapperPath, `#!/bin/sh\nexec ${shellQuote(process.execPath)} "\${0%/*}/security.mjs" "$@"\n`, { mode: 0o755 });
	chmodSync(wrapperPath, 0o755);
	if (fail) writeFileSync(join(dir, "fail"), "forced failure\n");

	const previous = process.env.PATH;
	process.env.PATH = hard ? dir : `${dir}:${previous ?? ""}`;
	t.after(() => {
		if (previous === undefined) delete process.env.PATH;
		else process.env.PATH = previous;
		rmSync(dir, { recursive: true, force: true });
	});

	return { dir, wrapperPath, storePath, readStore: () => readStubStore(storePath) };
}
