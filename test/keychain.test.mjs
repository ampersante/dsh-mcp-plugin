import test from "node:test";
import assert from "node:assert/strict";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	statSync,
	writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { installSecurityStub, setStubMarker } from "./support/security.mjs";

// `oauth.js` resolves STATE_PATH when it is imported, so DSH_HOME must exist
// first. Tests below use one home and distinct account names.
process.env.DSH_HOME = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-keychain-"));
const DSH_HOME = process.env.DSH_HOME;

const oauth = await import("../oauth.js");
const { createOAuthProvider } = oauth;

const KEYCHAIN_SERVICE = "dsh-mcp-oauth";
const SERVER_URL = "https://mcp.example/mcp";
const SERVER_URL_A = "https://one.example/mcp";
const SERVER_URL_B = "https://two.example/mcp";
const STATE_PATH = join(DSH_HOME, "mcp-oauth");

function provider(serverName, serverUrl = SERVER_URL) {
	return createOAuthProvider({ serverName, serverUrl, oauth: { enabled: true, callbackPort: 8765 } });
}

function storedFile(serverName) {
	return join(STATE_PATH, `${serverName}.json`);
}

function keychainKey(serverName) {
	return `${KEYCHAIN_SERVICE}/${serverName}`;
}

/** The file store holds raw JSON; the Keychain store holds its base64. */
function fileState(serverName) {
	try {
		return JSON.parse(readFileSync(storedFile(serverName), "utf8"));
	} catch {
		return null;
	}
}

function seedKeychain(stub, serverName, state) {
	const store = stub.readStore();
	store[keychainKey(serverName)] = Buffer.from(JSON.stringify(state), "utf8").toString("base64");
	writeFileSync(stub.storePath, `${JSON.stringify(store)}\n`);
}

function seedFile(serverName, state) {
	mkdirSync(STATE_PATH, { recursive: true, mode: 0o700 });
	writeFileSync(storedFile(serverName), JSON.stringify(state), { mode: 0o600 });
}

function keychainState(stub, serverName) {
	const encoded = stub.readStore()[keychainKey(serverName)];
	return encoded === undefined ? null : JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
}

/** Poll a stub barrier; the stub runs in another process, so waiting is asynchronous. */
async function waitUntil(predicate, description, timeout = 5000) {
	const started = Date.now();
	while (!predicate()) {
		if (Date.now() - started > timeout) throw new Error(`timed out waiting for ${description}`);
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
}

const token = (name) => ({ access_token: name, token_type: "Bearer" });

// ── Existing behaviour, kept as guards ──────────────────────────────────────

test("tokens round-trip through the Keychain and leave no file copy", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "keychain-roundtrip";
	const tokens = { access_token: "keychain-token", token_type: "Bearer", refresh_token: "refresh-1", expires_in: 3600 };

	await provider(serverName).saveTokens(tokens);
	assert.deepEqual(Object.keys(stub.readStore()), [keychainKey(serverName)], "the write must reach the security stub");

	// load() caches state in the instance, so only a fresh provider proves the read path.
	const fresh = provider(serverName);
	assert.deepEqual(await fresh.tokens(), tokens);
	assert.equal(existsSync(storedFile(serverName)), false, "the file store must stay unused while the Keychain works");
});

test("an oversized credential replaces the Keychain entry and is read whole from the file", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "keychain-oversized";
	await provider(serverName).saveTokens(token("previous-token"));
	assert.deepEqual(Object.keys(stub.readStore()), [keychainKey(serverName)], "the small credential must start in the Keychain");

	const tokens = { access_token: "large-token", token_type: "Bearer", blob: "x".repeat(5000) };
	await provider(serverName).saveTokens(tokens);

	assert.deepEqual(stub.readStore(), {}, "the oversized value and its stale Keychain copy must not remain");
	const path = storedFile(serverName);
	assert.ok(existsSync(path), "the oversized credential must land in the file store");
	assert.equal(statSync(path).mode & 0o777, 0o600);
	assert.deepEqual(await provider(serverName).tokens(), tokens, "a fresh provider must read the new credential back whole");
});

test("a refused Keychain write falls back to a 0600 file when no entry exists", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["failwrites"] });
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

	await first.saveTokens(token("revoked-token"));
	assert.deepEqual(Object.keys(stub.readStore()), [keychainKey(serverName)], "the token must start in the stub's Keychain");

	await first.invalidateCredentials("all");
	assert.deepEqual(stub.readStore(), {}, "security delete-generic-password must remove the Keychain entry");
	assert.equal(existsSync(storedFile(serverName)), false);

	const fresh = provider(serverName);
	assert.equal(await fresh.tokens(), undefined);
});

// ── K1–K19: one live copy, fatal unknown errors, resource filtering ─────────

// K1 guard: the fallback is legitimate only when the Keychain has no record.
test("K1: a refused write with no existing entry falls back to the file", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["failwrites"] });
	const serverName = "k1-guard";
	const tokens = token("fallback-token");

	await provider(serverName).saveTokens(tokens);

	assert.deepEqual(stub.readStore(), {}, "the Keychain must hold nothing");
	assert.deepEqual(fileState(serverName).tokens, tokens, "the new value must be in the file");
	assert.equal(statSync(storedFile(serverName)).mode & 0o777, 0o600);
	assert.deepEqual(await provider(serverName).tokens(), tokens, "a fresh provider must read the file copy");
});

// K2: a stale Keychain entry must not shadow the value that was just written.
test("K2: a failed write replaces a stale Keychain entry so the new token wins", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["failwrites"] });
	const serverName = "k2-replace";
	seedKeychain(stub, serverName, { resourceUrl: SERVER_URL, tokens: token("token-one") });

	const second = token("token-two");
	await provider(serverName).saveTokens(second);

	assert.deepEqual(await provider(serverName).tokens(), second, "the fresh provider must read the new token, not the stale one");
	assert.deepEqual(stub.readStore(), {}, "the stale Keychain entry must be gone");
});

// K3: nothing may be changed when the stale entry cannot be removed.
test("K3: an undeletable Keychain entry aborts the save and leaves the old one", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["failwrites", "faildeletes"] });
	const serverName = "k3-abort";
	const first = token("token-one");
	seedKeychain(stub, serverName, { resourceUrl: SERVER_URL, tokens: first });

	await assert.rejects(provider(serverName).saveTokens(token("token-two")), "the save must fail when the old entry cannot be removed");

	assert.equal(keychainState(stub, serverName).tokens.access_token, "token-one", "the old entry must survive unchanged");
	assert.equal(existsSync(storedFile(serverName)), false, "no file copy may be written");
});

// K4: an unknown read error is fatal, unlike the "no record" answer.
test("K4: an unknown Keychain read error aborts the save instead of using a file", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true, markers: ["failfinds", "failwrites"] });
	const serverName = "k4-findfail";

	await assert.rejects(provider(serverName).saveTokens(token("token")), "an unknown read error must abort the save");
	assert.equal(existsSync(storedFile(serverName)), false, "the save must not leave a file copy");
});

// K5 guard: without security(1) the file is the only store.
test("K5: without security(1) the credential goes to a 0600 file", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { missing: true });
	const serverName = "k5-missing";
	const tokens = token("no-security-token");

	await provider(serverName).saveTokens(tokens);

	assert.deepEqual(fileState(serverName).tokens, tokens);
	assert.equal(statSync(storedFile(serverName)).mode & 0o777, 0o600);
	assert.deepEqual(await provider(serverName).tokens(), tokens);
});

// K6: promoting a file credential into the Keychain removes the file copy.
test("K6: a working Keychain takes over and the stale file copy is removed", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["failwrites"] });
	const serverName = "k6-promote";
	await provider(serverName).saveTokens(token("token-one"));
	assert.ok(existsSync(storedFile(serverName)), "the first save must land in the file");

	setStubMarker(stub, "failwrites", false);
	const third = token("token-three");
	await provider(serverName).saveTokens(third);

	assert.equal(existsSync(storedFile(serverName)), false, "the stale file copy must be gone");
	assert.deepEqual(await provider(serverName).tokens(), third, "the new token must be readable");
});

// K7: a failed file removal is fatal and happens before the Keychain write.
test("K7: a fatal file removal aborts the save before the Keychain is touched", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["failwrites"] });
	const serverName = "k7-rmfail";
	const first = token("token-one");
	await provider(serverName).saveTokens(first);
	assert.ok(existsSync(storedFile(serverName)), "the first save must land in the file");
	setStubMarker(stub, "failwrites", false);

	chmodSync(STATE_PATH, 0o500);
	try {
		await assert.rejects(provider(serverName).saveTokens(token("token-two")), "a failed file removal must abort the save");
	} finally {
		chmodSync(STATE_PATH, 0o700);
	}

	assert.deepEqual(await provider(serverName).tokens(), first, "the old credential must survive");
});

// K8: an oversized credential still has to remove the stale Keychain entry.
test("K8: an oversized credential aborts when the stale entry cannot be deleted", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "k8-oversized";
	seedKeychain(stub, serverName, { resourceUrl: SERVER_URL, tokens: token("token-one") });
	setStubMarker(stub, "faildeletes");

	const oversized = { access_token: "huge-token", token_type: "Bearer", blob: "x".repeat(5000) };
	await assert.rejects(provider(serverName).saveTokens(oversized), "an undeletable stale entry must abort the oversized save");
	assert.equal(existsSync(storedFile(serverName)), false, "the oversized value must not land in the file");
});

// K9: revoking tokens keeps the client registration.
test("K9: invalidating tokens keeps the client registration", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true });
	const serverName = "k9-tokens";
	const client = { client_id: "client-1" };
	const first = provider(serverName);
	await first.saveClientInformation(client);
	await first.saveTokens(token("token-one"));

	await first.invalidateCredentials("tokens");

	const fresh = provider(serverName);
	assert.deepEqual(await fresh.clientInformation(), client, "the client registration must survive");
	assert.equal(await fresh.tokens(), undefined, "the token must be gone");
});

// K10: another resource never inherits the first resource's token.
test("K10: another resource never inherits the first resource's token", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true });
	const serverName = "k10-resource";
	await provider(serverName, SERVER_URL_A).saveTokens(token("token-a"));

	const b = provider(serverName, SERVER_URL_B);
	const client = { client_id: "client-b" };
	await b.saveClientInformation(client);

	assert.equal(await b.tokens(), undefined, "the other resource's token must not be visible");
	assert.deepEqual(await b.clientInformation(), client, "the client registration must still be stored");
});

// K11: revocation fails when the Keychain entry cannot be removed.
test("K11: a failed Keychain delete aborts revocation", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "k11-revoke";
	const first = provider(serverName);
	await first.saveTokens(token("token-one"));
	setStubMarker(stub, "faildeletes");

	await assert.rejects(first.invalidateCredentials("all"), "revocation must fail when its copy cannot be removed");
	assert.ok(Object.hasOwn(stub.readStore(), keychainKey(serverName)), "the entry must not disappear silently");
});

// K12: the strict read in persist() turns an unknown error into a failed save.
test("K12: an unknown Keychain read error aborts client registration and writes nothing", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["failfinds"] });
	const serverName = "k12-client";

	await assert.rejects(provider(serverName).saveClientInformation({ client_id: "client-1" }), "the registration must not be written");

	assert.deepEqual(stub.readStore(), {}, "the Keychain stub must be unchanged");
	assert.equal(existsSync(storedFile(serverName)), false, "no file copy may be written");
});

// K13: a failed save rolls back to the last stored token, and a later save recovers.
test("K13: a failed save keeps the last stored token for the same provider", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "k13-rollback";
	const first = provider(serverName);
	const one = token("token-one");
	await first.saveTokens(one);
	setStubMarker(stub, "faildeletes");

	await assert.rejects(first.saveTokens(token("token-two")), "the save must fail");
	assert.deepEqual(await first.tokens(), one, "the same provider must report the last stored token");

	setStubMarker(stub, "faildeletes", false);
	const three = token("token-three");
	await first.saveTokens(three);
	assert.deepEqual(await first.tokens(), three, "a later save must recover");
});

// K14: a missing record is a normal outcome, not an error.
test("K14: removing an absent Keychain entry reports it as gone", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true });
	assert.equal(typeof oauth.removeKeychainEntry, "function", "removeKeychainEntry must be exported");
	assert.equal(await oauth.removeKeychainEntry("k14-absent"), "gone");
});

// K15 guard: a corrupted Keychain write is discarded and the value goes to the file.
test("K15: a corrupted Keychain write is removed and the value goes to the file", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["corruptadd"] });
	const serverName = "k15-corrupt";
	const tokens = token("honest-token");

	await provider(serverName).saveTokens(tokens);

	assert.deepEqual(stub.readStore(), {}, "the corrupted entry must be removed");
	assert.deepEqual(fileState(serverName).tokens, tokens, "the file must hold the value that was passed");
	assert.deepEqual(await provider(serverName).tokens(), tokens);
});

// K16: a corrupted write whose cleanup is refused must not leave a file copy.
test("K16: a corrupted write whose cleanup is refused aborts without a file copy", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true, markers: ["corruptadd", "faildeletes2"] });
	const serverName = "k16-corrupt-cleanup";

	await assert.rejects(provider(serverName).saveTokens(token("token")), "the refused cleanup must abort the save");
	assert.equal(existsSync(storedFile(serverName)), false, "no file copy may be written");
});

// K17: a file for another resource must not fill a null field of this resource.
test("K17: a token file for another resource never fills this resource's entry", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "k17-pair";
	seedKeychain(stub, serverName, { resourceUrl: SERVER_URL_A, tokens: null, clientInformation: { client_id: "client-a" } });
	seedFile(serverName, { resourceUrl: SERVER_URL_B, tokens: token("token-b") });

	assert.equal(await provider(serverName, SERVER_URL_A).tokens(), undefined, "the other resource's token must not be reused");
});

// K18: a failed save after revocation must not resurrect the revoked token.
test("K18: a failed save after revocation cannot bring the revoked token back", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "k18-revoked";
	const first = provider(serverName);
	await first.saveTokens(token("token-one"));
	await first.invalidateCredentials("all");
	setStubMarker(stub, "failfinds");

	await assert.rejects(first.saveCodeVerifier("v"), "the save must fail");
	assert.equal(await first.tokens(), undefined, "the revoked token must not come back");
});

// K19: a failed save must not restore a client that belongs to another resource.
test("K19: a failed save cannot restore a client from another resource", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true, markers: ["failfinds"] });
	const serverName = "k19-foreign-client";
	seedFile(serverName, { resourceUrl: SERVER_URL_A, clientInformation: { client_id: "client-a" } });

	const b = provider(serverName, SERVER_URL_B);
	await assert.rejects(b.saveCodeVerifier("v"), "the save must fail");
	assert.equal(await b.clientInformation(), undefined, "another resource's client must not be restored");
});

// ── K20–K22: ambiguous add, overlapping fields, revocation order ───────────

// K20: `security -i` can store the value and still exit non-zero. The save must
// read the Keychain back and keep the single copy instead of writing a file.
test("K20: an add that stored its value and then failed leaves one Keychain copy", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["addthenfail"] });
	const serverName = "k20-add-then-fail";
	const tokens = token("landed-token");

	await provider(serverName).saveTokens(tokens);

	assert.deepEqual(Object.keys(stub.readStore()), [keychainKey(serverName)], "the Keychain must hold the only copy");
	assert.deepEqual(keychainState(stub, serverName), {
		clientInformation: null,
		tokens,
		codeVerifier: null,
		discoveryState: null,
		authorizationServerUrl: null,
		resourceUrl: SERVER_URL
	});
	assert.equal(existsSync(storedFile(serverName)), false, "no file copy may be written after the value landed");
	assert.deepEqual(await provider(serverName).tokens(), tokens, "a fresh provider must read the one copy back");
});

// K20b: the read-back is only a reconciliation when the value matches; a
// different value leaves the Keychain state unknown, so the save must fail
// closed instead of writing a second copy.
test("K20b: a failed add whose Keychain value differs aborts without a file", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true, markers: ["corruptadd", "addthenfail"] });
	const serverName = "k20b-add-then-fail";

	await assert.rejects(provider(serverName).saveTokens(token("honest-token")), (error) => {
		assert.equal(error.name, "KeychainUnknown", "the failure must be reported as an unknown Keychain state");
		assert.match(error.message, /different value/);
		return true;
	});
	assert.equal(existsSync(storedFile(serverName)), false, "no file copy may be written while the Keychain is unknown");
});

// K20c: a helper that vanishes after a failed add makes the result unknowable:
// `unavailable` no longer proves the Keychain is empty, so no file may appear.
test("K20c: an add that stored its value and then lost security(1) aborts without a file", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["addthenvanish"] });
	const serverName = "k20c-add-then-vanish";
	const tokens = token("landed-token");

	await assert.rejects(provider(serverName).saveTokens(tokens), (error) => {
		assert.equal(error.name, "KeychainUnknown", "the failure must be reported as an unknown Keychain state");
		assert.match(error.message, /cannot be verified/, "the message must say the Keychain write result cannot be checked");
		return true;
	});

	assert.equal(existsSync(storedFile(serverName)), false, "no file copy may be written while the Keychain is unknown");
	assert.deepEqual(keychainState(stub, serverName).tokens, tokens, "the Keychain must still hold the value the add stored");
});

// K20d: the same hole on the success path — an add that reported success and a
// helper that vanished before verification cannot justify a file copy either.
test("K20d: a successful add whose helper vanishes before verification aborts without a file", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["addsucceedvanish"] });
	const serverName = "k20d-add-verify-vanish";
	const tokens = token("landed-token");

	await assert.rejects(provider(serverName).saveTokens(tokens), (error) => {
		assert.equal(error.name, "KeychainUnknown", "the failure must be reported as an unknown Keychain state");
		assert.match(error.message, /cannot be verified/, "the message must say the Keychain write result cannot be checked");
		return true;
	});

	assert.equal(existsSync(storedFile(serverName)), false, "no file copy may be written while the Keychain is unknown");
	assert.deepEqual(keychainState(stub, serverName).tokens, tokens, "the Keychain must still hold the value the add stored");
});

// K20f: security(1) confirms the deletion on stdout but exits non-zero
// (observed on macOS, code 161). A confirmed deletion is a removal: the save
// must proceed instead of reporting an unknown state.
test("K20f: a deletion confirmed on stdout counts as gone despite a non-zero exit", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["deleteconfirmcode"] });
	const serverName = "k20f-delete-confirmed";
	const tokens = token("fresh-token");

	await provider(serverName).saveTokens(tokens);

	const fresh = provider(serverName);
	assert.deepEqual(await fresh.tokens(), tokens, "the credential must be readable after a confirmed deletion");
	assert.equal(existsSync(storedFile(serverName)), false, "the Keychain copy must be the only one");
	assert.equal(await oauth.removeKeychainEntry(serverName), "gone", "the exported helper must report the confirmed removal");
});

// K20e: verification reads a mismatched value, then the helper disappears
// before cleanup. An unconfirmed removal is an unknown state, not permission
// to write a file next to the record that may still be there.
test("K20e: a mismatched value whose cleanup cannot run aborts without a file", { timeout: 20000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true, markers: ["corruptadd", "findvanish"] });
	const serverName = "k20e-mismatch-vanish";
	const tokens = token("landed-token");

	await assert.rejects(provider(serverName).saveTokens(tokens), (error) => {
		assert.equal(error.name, "KeychainUnknown", "the failure must be reported as an unknown Keychain state");
		assert.match(error.message, /may still be there/, "the message must say the stale entry may survive");
		return true;
	});

	assert.equal(existsSync(storedFile(serverName)), false, "no file copy may be written while the Keychain state is unknown");
});

// K21: a save that waits in the queue must apply the values it captured, not
// whatever a task ahead of it left in this.store.
test("K21: overlapping saves of different fields keep both new values", { timeout: 30000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "k21-overlap";
	const first = provider(serverName);
	await first.saveClientInformation({ client_id: "old-client" });
	await first.saveTokens(token("old"));

	setStubMarker(stub, "holdwrites");
	const newTokens = token("new");
	const newClient = { client_id: "new-client" };
	const savingTokens = first.saveTokens(newTokens);
	await waitUntil(() => existsSync(join(stub.dir, "add-waiting")), "the token save to reach the Keychain");
	const savingClient = first.saveClientInformation(newClient);
	// Let the client save capture its values and queue behind the held write.
	await new Promise((resolve) => setTimeout(resolve, 50));
	setStubMarker(stub, "holdwrites", false);
	await Promise.all([savingTokens, savingClient]);

	const fresh = provider(serverName);
	assert.deepEqual(await fresh.tokens(), newTokens, "the new token must survive the overlap");
	assert.deepEqual(await fresh.clientInformation(), newClient, "the new client registration must survive the overlap");
});

// K22: a save already in flight must not write the token back after a
// completed revocation.
test("K22: a save in flight cannot restore a token after invalidateCredentials('all')", { timeout: 30000 }, async (t) => {
	const stub = installSecurityStub(t, { hard: true });
	const serverName = "k22-late-save";
	const first = provider(serverName);
	await first.saveTokens(token("old"));

	setStubMarker(stub, "holdwrites");
	const saving = first.saveTokens(token("new"));
	await waitUntil(() => existsSync(join(stub.dir, "add-waiting")), "the delayed save to reach the Keychain");
	let revoked = false;
	const revoking = first.invalidateCredentials("all").then(() => { revoked = true; });
	await new Promise((resolve) => setTimeout(resolve, 100));
	const premature = revoked;
	setStubMarker(stub, "holdwrites", false);
	await Promise.all([saving, revoking]);

	assert.equal(premature, false, "revocation must wait for the save in flight");
	assert.equal(await provider(serverName).tokens(), undefined, "the delayed save must not restore the token");
	assert.deepEqual(stub.readStore(), {}, "no Keychain copy may survive the revocation");
});
