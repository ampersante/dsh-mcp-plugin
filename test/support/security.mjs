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
 *
 * Failure modes are marker files in the same directory, so a test can turn
 * them on and off while a provider keeps its queue:
 * - `fail`        every invocation exits 1 (unknown failure);
 * - `failwrites`  only `-i` (the add command) exits 36;
 * - `faildeletes` only `delete-generic-password` exits 36;
 * - `faildeletes2` the second `delete-generic-password` exits 36. The count
 *   lives in `delete-count`: every stub run is a separate process, so memory
 *   would not survive between two calls. The counter is only consulted while
 *   this marker exists;
 * - `failfinds`   only `find-generic-password` exits 36;
 * - `corruptadd`  `-i` stores a value different from the one it was given;
 * - `addthenfail` `-i` stores the value and only then exits 36, the ambiguous
 *   outcome of a write that may have landed before its error;
 * - `addthenvanish` `-i` stores the value, deletes its own wrapper so no later
 *   `security` call can answer, and exits 36 — a landed write whose result is
 *   unknowable;
 * - `addsucceedvanish` the same, but `-i` exits 0, so only the verification
 *   read finds the helper gone;
 * - `holdwrites`  `-i` pauses before it reads stdin, writing `add-waiting`
 *   first, until this marker disappears; a test can keep a save in flight.
 *
 * A missing record answers 44 with the message the real tool prints.
 */
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const STUB_SOURCE = String.raw`import { existsSync, readFileSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const storePath = join(here, "store.json");
const NOT_FOUND = "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.";

function marker(name) {
	return existsSync(join(here, name));
}

/** Exit like the real tool: the message on stderr, the given status. */
function refuse(message, code = 1) {
	writeSync(2, "stub security: " + message + "\n");
	process.exit(code);
}

if (marker("fail")) refuse("forced failure");

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
	if (marker("failfinds")) refuse("forced find failure", 36);
	const key = valueOf(args, "-s") + "/" + valueOf(args, "-a");
	const store = readStore();
	if (!Object.hasOwn(store, key)) {
		writeSync(2, NOT_FOUND + "\n");
		process.exit(44);
	}
	process.stdout.write(store[key] + "\n");
	if (marker("findvanish")) {
		// The read answers, then the helper disappears: the cleanup call that
		// follows gets ENOENT and cannot confirm the removal.
		rmSync(join(here, "security"), { force: true });
		process.exit(0);
	}
} else if (command === "delete-generic-password") {
	if (marker("faildeletes")) refuse("forced delete failure", 36);
	if (marker("faildeletes2")) {
		const counterPath = join(here, "delete-count");
		let count = 0;
		try {
			count = Number(readFileSync(counterPath, "utf8").trim()) || 0;
		} catch {}
		count += 1;
		writeFileSync(counterPath, count + "\n");
		if (count >= 2) refuse("forced second delete failure", 36);
	}
	const key = valueOf(args, "-s") + "/" + valueOf(args, "-a");
	const store = readStore();
	if (!Object.hasOwn(store, key)) {
		writeSync(2, NOT_FOUND + "\n");
		process.exit(44);
	}
	delete store[key];
	writeStore(store);
	if (marker("deleteconfirmcode")) {
		// The real tool can confirm the deletion on stdout and still exit
		// non-zero; the store is already updated above.
		process.stdout.write("password has been deleted.\n");
		process.exit(161);
	}
} else if (command === "-i") {
	if (marker("failwrites")) refuse("forced write failure", 36);
	if (marker("holdwrites")) {
		writeFileSync(join(here, "add-waiting"), "waiting\n");
		while (marker("holdwrites")) await new Promise((resolve) => setTimeout(resolve, 5));
	}
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
		store[key] = (marker("corruptadd") || marker("corruptvanish"))
			? Buffer.from("corrupt-value", "utf8").toString("base64")
			: valueOf(words, "-w");
	}
	writeStore(store);
	if (marker("addthenfail")) refuse("forced failure after the value was stored", 36);
	if (marker("addthenvanish")) {
		// The wrapper is already gone from the running shell's point of view, so
		// every later call finds no security(1) at all.
		rmSync(join(here, "security"), { force: true });
		refuse("forced failure after the value was stored and the helper vanished", 36);
	}
	if (marker("addsucceedvanish")) {
		rmSync(join(here, "security"), { force: true });
		process.exit(0);
	}
	if (marker("corruptvanish")) {
		// A mismatched value lands, then the helper disappears before cleanup.
		rmSync(join(here, "security"), { force: true });
		process.exit(0);
	}
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
 * Turn one failure mode on or off after installation. The stub reads the
 * marker file on every invocation, so a running provider picks the change up
 * on its next `security` call.
 */
export function setStubMarker(stub, name, enabled = true) {
	const path = join(stub.dir, name);
	if (enabled) writeFileSync(path, "marker\n");
	else rmSync(path, { force: true });
}

/**
 * Install the stub for one test and restore PATH afterwards.
 *
 * `fail: true` is shorthand for the `fail` marker: every invocation exits 1.
 * `markers` lists the other modes to enable up front. `hard: true` leaves only
 * the stub directory in PATH, so a missed stub cannot silently reach the real
 * Keychain. `missing: true` leaves PATH pointing at a directory without a
 * `security` file at all, which exercises the ENOENT path.
 */
export function installSecurityStub(t, { fail = false, hard = false, missing = false, markers = [] } = {}) {
	const dir = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-security-"));
	const wrapperPath = join(dir, "security");
	const storePath = join(dir, "store.json");
	if (!missing) {
		writeFileSync(join(dir, "security.mjs"), STUB_SOURCE, { mode: 0o644 });
		writeFileSync(wrapperPath, `#!/bin/sh\nexec ${shellQuote(process.execPath)} "\${0%/*}/security.mjs" "$@"\n`, { mode: 0o755 });
		chmodSync(wrapperPath, 0o755);
	}
	if (fail) writeFileSync(join(dir, "fail"), "forced failure\n");
	for (const marker of markers) writeFileSync(join(dir, marker), "marker\n");

	const previous = process.env.PATH;
	process.env.PATH = missing || hard ? dir : `${dir}:${previous ?? ""}`;
	t.after(() => {
		if (previous === undefined) delete process.env.PATH;
		else process.env.PATH = previous;
		rmSync(dir, { recursive: true, force: true });
	});

	return { dir, wrapperPath, storePath, readStore: () => readStubStore(storePath) };
}
