import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { installSecurityStub } from "./support/security.mjs";

// `oauth.js` resolves STATE_PATH when it is imported, so DSH_HOME must exist
// first. Tests below use one home and distinct account names.
process.env.DSH_HOME = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-keychain-"));
const DSH_HOME = process.env.DSH_HOME;

const { createOAuthProvider } = await import("../oauth.js");

const KEYCHAIN_SERVICE = "dsh-mcp-oauth";
const SERVER_URL = "https://mcp.example/mcp";

function provider(serverName) {
	return createOAuthProvider({ serverName, serverUrl: SERVER_URL, oauth: { enabled: true, callbackPort: 8765 } });
}

function storedFile(serverName) {
	return join(DSH_HOME, "mcp-oauth", `${serverName}.json`);
}

test("tokens round-trip through the Keychain and leave no file copy", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "keychain-roundtrip";
	const tokens = { access_token: "keychain-token", token_type: "Bearer", refresh_token: "refresh-1", expires_in: 3600 };

	await provider(serverName).saveTokens(tokens);
	assert.deepEqual(Object.keys(stub.readStore()), [`${KEYCHAIN_SERVICE}/${serverName}`], "the write must reach the security stub");

	// load() caches state in the instance, so only a fresh provider proves the read path.
	const fresh = provider(serverName);
	assert.deepEqual(await fresh.tokens(), tokens);
	assert.equal(existsSync(storedFile(serverName)), false, "the file store must stay unused while the Keychain works");
});

test("an oversized credential replaces the Keychain entry and is read whole from the file", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "keychain-oversized";
	await provider(serverName).saveTokens({ access_token: "previous-token", token_type: "Bearer" });
	assert.deepEqual(Object.keys(stub.readStore()), [`${KEYCHAIN_SERVICE}/${serverName}`], "the small credential must start in the Keychain");

	const tokens = { access_token: "large-token", token_type: "Bearer", blob: "x".repeat(5000) };
	await provider(serverName).saveTokens(tokens);

	assert.deepEqual(stub.readStore(), {}, "the oversized value and its stale Keychain copy must not remain");
	const path = storedFile(serverName);
	assert.ok(existsSync(path), "the oversized credential must land in the file store");
	assert.equal(statSync(path).mode & 0o777, 0o600);
	assert.deepEqual(await provider(serverName).tokens(), tokens, "a fresh provider must read the new credential back whole");
});

test("a failing Keychain falls back to a 0600 file", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { fail: true, hard: true });
	const serverName = "keychain-fallback";
	const tokens = { access_token: "file-token", token_type: "Bearer", expires_in: 3600 };

	const lines = [];
	const original = console.error;
	console.error = (...args) => { lines.push(args.map(String).join(" ")); };
	try {
		await provider(serverName).saveTokens(tokens);
	} finally {
		console.error = original;
	}

	assert.ok(lines.some((line) => line.includes("Keychain unavailable")), `expected a Keychain fallback notice, got ${JSON.stringify(lines)}`);
	const path = storedFile(serverName);
	assert.ok(existsSync(path), "the fallback file must exist");
	assert.equal(statSync(path).mode & 0o777, 0o600);
	assert.deepEqual(await provider(serverName).tokens(), tokens);
	assert.deepEqual(stub.readStore(), {}, "the failing stub must not store anything");
});

test("revoking credentials deletes the Keychain entry, not just the file", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "keychain-revoke";
	const first = provider(serverName);

	await first.saveTokens({ access_token: "revoked-token", token_type: "Bearer" });
	assert.deepEqual(Object.keys(stub.readStore()), [`${KEYCHAIN_SERVICE}/${serverName}`], "the token must start in the stub's Keychain");

	await first.invalidateCredentials("all");
	assert.deepEqual(stub.readStore(), {}, "security delete-generic-password must remove the Keychain entry");
	assert.equal(existsSync(storedFile(serverName)), false);

	const fresh = provider(serverName);
	assert.equal(await fresh.tokens(), undefined);
});
