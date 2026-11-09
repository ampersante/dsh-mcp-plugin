import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { compare } from "../tools/version.mjs";

process.env.DSH_HOME = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-test-"));
const DSH_HOME = process.env.DSH_HOME;
const STATE_PATH = join(DSH_HOME, "mcp-oauth");
const OAUTH_URL = new URL("../oauth.js", import.meta.url).href;
const UPDATE_SCRIPT = fileURLToPath(new URL("../tools/update.mjs", import.meta.url));
const oauth = await import("../oauth.js");
const { CallbackHub, createOAuthProvider } = oauth;
const { installSecurityStub } = await import("./support/security.mjs");

async function hubOn(t) {
	const hub = new CallbackHub(0);
	const server = await hub.ensure();
	t.after(() => hub.close());
	return { hub, port: server.address().port };
}

/** A port nobody listens on right now; the listener is closed before returning. */
function freePort() {
	return new Promise((resolve, reject) => {
		const probe = createNetServer();
		probe.once("error", reject);
		probe.listen(0, "127.0.0.1", () => {
			const { port } = probe.address();
			probe.close(() => resolve(port));
		});
	});
}

test("a malformed percent escape answers 400 instead of throwing", async (t) => {
	const { port } = await hubOn(t);
	const response = await fetch(`http://127.0.0.1:${port}/callback/%E0%A4%A`);
	assert.equal(response.status, 400);
});

test("a second registration for the same server is refused, not silently replaced", async (t) => {
	const { hub } = await hubOn(t);
	hub.register("dup", "s").promise.catch(() => {});
	assert.throws(() => hub.register("dup", "s2"), /already pending/);
});

test("the reply waits for the exchange, so a failure cannot look like success", async (t) => {
	const { hub, port } = await hubOn(t);
	const flow = hub.register("gamma", "state-1");
	const pending = fetch(`http://127.0.0.1:${port}/callback/gamma?code=c&state=state-1`);
	const { code, respond } = await flow.promise;
	assert.equal(code, "c");
	respond(500, "<p>exchange failed</p>");
	const response = await pending;
	assert.equal(response.status, 500);
	assert.match(await response.text(), /exchange failed/);
});

test("callback markup escapes a hostile server name", async (t) => {
	const { port } = await hubOn(t);
	const response = await fetch(`http://127.0.0.1:${port}/callback/%3Cimg%20src%3Dx%3E?code=c&state=s`);
	const body = await response.text();
	assert.equal(response.status, 409);
	assert.ok(!body.includes("<img"), "raw markup must not survive");
	assert.match(body, /&lt;img/);
});

test("revoking credentials deletes the file copy as well", async (t) => {
	installSecurityStub(t, { hard: true });
	const provider = createOAuthProvider({ serverName: "revoke-me", serverUrl: "https://mcp.example/mcp", oauth: { enabled: true, callbackPort: 8799 } });
	await provider.saveTokens({ access_token: "secret", token_type: "Bearer" });
	assert.ok(await provider.tokens());
	await provider.invalidateCredentials("all");
	assert.equal(await provider.tokens(), undefined);
});

test("credentials issued for another resource are not reused", async (t) => {
	installSecurityStub(t, { hard: true });
	const a = createOAuthProvider({ serverName: "shared-name", serverUrl: "https://one.example/mcp", oauth: { enabled: true, callbackPort: 8798 } });
	await a.saveTokens({ access_token: "token-one", token_type: "Bearer" });
	const b = createOAuthProvider({ serverName: "shared-name", serverUrl: "https://two.example/mcp", oauth: { enabled: true, callbackPort: 8798 } });
	assert.equal(await b.tokens(), undefined);
});

// ── H1–H5: input validation, missing helpers, deadlines, file hygiene ───────

// H1: a server name reaches paths and shell commands, so it is checked first.
test("H1: a malformed server name is refused before anything is touched", () => {
	for (const serverName of ["../x", "a b", "a\nb", "a".repeat(33)]) {
		assert.throws(
			() => createOAuthProvider({ serverName, serverUrl: "https://mcp.example/mcp", oauth: { callbackPort: 8797 } }),
			`the name ${JSON.stringify(serverName)} must be refused`,
		);
	}
	assert.doesNotThrow(
		() => createOAuthProvider({ serverName: "alphaxiv", serverUrl: "https://mcp.example/mcp", oauth: { callbackPort: 8796 } }),
		"a plain account name must be accepted",
	);
});

// H2: a machine without `open` must not take the whole process down.
test("H2: a missing open(1) does not crash the process", { timeout: 20000 }, async (t) => {
	const root = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-h2-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	const home = join(root, "home");
	const emptyPath = join(root, "bin");
	mkdirSync(home);
	mkdirSync(emptyPath);
	const port = await freePort();

	const script = join(root, "child.mjs");
	writeFileSync(
		script,
		`import { createOAuthProvider } from ${JSON.stringify(OAUTH_URL)};
const provider = createOAuthProvider({ serverName: "h2-child", serverUrl: "https://mcp.example/mcp", oauth: { callbackPort: ${port} } });
await provider.redirectToAuthorization(new URL("https://as.example/authorize?state=state-1"));
await new Promise((resolve) => setTimeout(resolve, 400));
await provider.hub.close();
process.exit(0);
`,
	);
	const result = spawnSync(process.execPath, [script], {
		env: { ...process.env, DSH_HOME: home, PATH: emptyPath },
		encoding: "utf8",
		timeout: 15000,
	});
	assert.equal(
		result.status,
		0,
		`the child must survive a failed browser launch (status=${result.status}, signal=${result.signal}): ${result.stderr}`,
	);
});

// H3: a hung exchange must fail with a recognisable deadline error.
test("H3: withDeadline fails a hung promise and absorbs a late rejection", { timeout: 20000 }, async () => {
	let rejectLater;
	const hung = new Promise((resolve, reject) => { rejectLater = reject; });
	const unhandled = [];
	const onUnhandled = (reason) => unhandled.push(reason);
	process.on("unhandledRejection", onUnhandled);
	try {
		await assert.rejects(oauth.withDeadline(hung, 50), (error) => {
			assert.equal(error.code, "EDEADLINE", "a deadline error must carry its code");
			return true;
		});
		rejectLater(new Error("too late"));
		await new Promise((resolve) => setTimeout(resolve, 50));
		assert.deepEqual(unhandled, [], "a late rejection must not surface as unhandled");
	} finally {
		process.off("unhandledRejection", onUnhandled);
	}
	assert.equal(await oauth.withDeadline(Promise.resolve(42), 500), 42, "a fast promise must resolve with its value");
});

// H4: the state directory holds credential copies and is private.
test("H4: the state directory is 0700 after a file write", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true, markers: ["failwrites"] });
	mkdirSync(STATE_PATH, { recursive: true, mode: 0o755 });
	chmodSync(STATE_PATH, 0o755);

	const provider = createOAuthProvider({ serverName: "h4-dir", serverUrl: "https://mcp.example/mcp", oauth: { callbackPort: 8795 } });
	await provider.saveTokens({ access_token: "dir-token", token_type: "Bearer" });

	assert.equal(statSync(STATE_PATH).mode & 0o777, 0o700, "the directory must be private after the write");
});

// H5: abandoned temporary files must not outlive the write that replaces them.
test("H5: stale temporary files are swept on writes and revocations", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true, markers: ["failwrites"] });
	mkdirSync(STATE_PATH, { recursive: true, mode: 0o700 });
	const serverName = "h5-sweep";
	const stale = join(STATE_PATH, `${serverName}.json.1.ab.tmp`);
	const provider = createOAuthProvider({ serverName, serverUrl: "https://mcp.example/mcp", oauth: { callbackPort: 8794 } });

	writeFileSync(stale, "stale");
	await provider.saveTokens({ access_token: "sweep-token", token_type: "Bearer" });
	assert.equal(existsSync(stale), false, "a file write must sweep stale temporaries");

	writeFileSync(stale, "stale again");
	await provider.invalidateCredentials("all");
	assert.equal(existsSync(stale), false, "revocation must sweep stale temporaries");
	assert.equal(await provider.tokens(), undefined);
});

// ── H6–H9: version ordering, ref validation, archive compatibility ─────────

// H6: build metadata never orders, and numeric prerelease identifiers must not
// go through Number, which loses precision past 2^53.
test("H6: build metadata never orders and huge numeric prerelease ids stay ordered", () => {
	assert.equal(compare("1.0.0-rc.1+build.2", "1.0.0-rc.1+build.3"), 0, "build metadata must not order");
	assert.equal(compare("1.2.3+build.1", "1.2.3"), 0, "a build of a release is the same version");
	assert.ok(compare("1.0.0-9007199254740992", "1.0.0-9007199254740993") < 0, "numeric identifiers past 2^53 must still compare");
});

// H10: core identifiers past 2^53 must order like decimal strings, since
// Number maps neighbouring integers onto the same double.
test("H10: huge core identifiers stay ordered and equal ones compare equal", () => {
	assert.ok(compare("9007199254740992.0.0", "9007199254740993.0.0") < 0, "a huge major must still order");
	assert.ok(compare("0.9007199254740992.0", "0.9007199254740993.0") < 0, "a huge minor must still order");
	assert.ok(compare("0.0.9007199254740992", "0.0.9007199254740993") < 0, "a huge patch must still order");
	assert.equal(compare("9007199254740993.0.0", "9007199254740993.0.0"), 0, "equal huge majors must compare equal");
	assert.equal(compare("0.9007199254740993.0", "0.9007199254740993.0"), 0, "equal huge minors must compare equal");
	assert.equal(compare("0.0.9007199254740993", "0.0.9007199254740993"), 0, "equal huge patches must compare equal");
});

/** A tag-only repository: enough for update.mjs, and it needs no network. */
function taggedRepo(t, { tag, authorize = false }) {
	const repo = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-update-repo-"));
	t.after(() => rmSync(repo, { recursive: true, force: true }));
	mkdirSync(join(repo, "test"), { recursive: true });
	mkdirSync(join(repo, "tools"), { recursive: true });
	const version = tag.replace(/^v/, "");
	writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "dsh-mcp-oauth", version, private: true, type: "module" }));
	writeFileSync(join(repo, "index.js"), "export {};\n");
	writeFileSync(join(repo, "oauth.js"), "export {};\n");
	writeFileSync(join(repo, "tools/version.mjs"), "export const compare = () => 0;\n");
	if (authorize) writeFileSync(join(repo, "tools/authorize.mjs"), "export {};\n");
	writeFileSync(join(repo, "test/smoke.test.mjs"), 'import test from "node:test";\nimport assert from "node:assert/strict";\ntest("smoke", () => assert.equal(1, 1));\n');
	const run = (...args) => spawnSync("git", ["-C", repo, ...args], { encoding: "utf8" });
	const config = ["-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"];
	for (const result of [
		run("init", "--quiet"),
		run("add", "-A"),
		run(...config, "commit", "--quiet", "-m", "initial"),
		run(...config, "tag", tag)
	]) {
		assert.equal(result.status, 0, `git failed: ${result.stderr}`);
	}
	return repo;
}

function updateArgs(repo, target, patch, ref, extra = []) {
	return [UPDATE_SCRIPT, "--repo", repo, "--ref", ref, "--target", target, "--patch", patch, "--node", process.execPath, ...extra];
}

// H7: a tag expression resolves to another object, so only the exact tag name
// may pass.
test("H7: update refuses a ref expression instead of a tag name", { timeout: 30000 }, (t) => {
	const repo = taggedRepo(t, { tag: "v0.1.0" });
	const root = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-update-check-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	for (const ref of ["v0.1.0^{tree}", "v0.1.0~0", "v0.1.0^0"]) {
		const result = spawnSync(process.execPath, updateArgs(repo, join(root, "target"), join(root, "patch.yml"), ref, ["--check"]), { encoding: "utf8", timeout: 20000 });
		assert.equal(result.status, 2, `--ref ${ref} must be refused, got ${result.status}: ${result.stdout}${result.stderr}`);
	}
});

// H8: an old tag has no tools/authorize.mjs; archiving it must still work.
test("H8: update archives a tag that predates tools/authorize.mjs", { timeout: 60000 }, (t) => {
	const repo = taggedRepo(t, { tag: "v0.1.0" });
	const root = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-update-old-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	const target = join(root, "installed");
	const patch = join(root, "cordis.patch.yml");
	writeFileSync(patch, "plugins: {}\n");

	const result = spawnSync(process.execPath, updateArgs(repo, target, patch, "v0.1.0"), { encoding: "utf8", timeout: 50000 });
	assert.equal(result.status, 0, `an old tag without tools/authorize.mjs must still install: ${result.stdout}${result.stderr}`);
	assert.ok(existsSync(join(target, "package.json")), "the tag must be installed");
	assert.ok(!existsSync(join(target, "tools", "authorize.mjs")), "a file the tag does not carry must not appear");
});

// H9: a current tag still ships the terminal authorizer.
test("H9: update still archives tools/authorize.mjs when the tag carries it", { timeout: 60000 }, (t) => {
	const repo = taggedRepo(t, { tag: "v0.2.0", authorize: true });
	const root = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-update-new-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	const target = join(root, "installed");
	const patch = join(root, "cordis.patch.yml");
	writeFileSync(patch, "plugins: {}\n");

	const result = spawnSync(process.execPath, updateArgs(repo, target, patch, "v0.2.0"), { encoding: "utf8", timeout: 50000 });
	assert.equal(result.status, 0, `a current tag must install: ${result.stdout}${result.stderr}`);
	assert.ok(existsSync(join(target, "tools", "authorize.mjs")), "the terminal authorizer must be exported with the tag");
});
