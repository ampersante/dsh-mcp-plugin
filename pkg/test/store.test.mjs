import test from "node:test";
import assert from "node:assert/strict";
import { mergeStores } from "../oauth.js";

const wrap = (o) => JSON.stringify(o);

test("keychain without tokens does not hide the token that the file holds", () => {
	const keychain = wrap({ clientInformation: { client_id: "abc" }, tokens: null, codeVerifier: "v1" });
	const file = wrap({ tokens: { access_token: "t1", token_type: "Bearer" }, codeVerifier: null });
	const merged = mergeStores(keychain, file);
	assert.equal(merged.tokens.access_token, "t1");
	assert.equal(merged.clientInformation.client_id, "abc");
	assert.equal(merged.codeVerifier, "v1");
});

test("keychain wins where both stores hold a value", () => {
	const keychain = wrap({ tokens: { access_token: "kc" } });
	const file = wrap({ tokens: { access_token: "file" } });
	assert.equal(mergeStores(keychain, file).tokens.access_token, "kc");
});

test("file fills fields the keychain leaves empty", () => {
	const keychain = wrap({ tokens: null, clientInformation: null });
	const file = wrap({ tokens: { access_token: "file" }, clientInformation: { client_id: "x" } });
	const merged = mergeStores(keychain, file);
	assert.equal(merged.tokens.access_token, "file");
	assert.equal(merged.clientInformation.client_id, "x");
});

test("corrupt stores degrade to the readable one", () => {
	assert.equal(mergeStores("{not json", wrap({ tokens: { access_token: "file" } })).tokens.access_token, "file");
	assert.equal(mergeStores(null, null), null);
});

test("empty state carries every field so a merge never yields undefined", () => {
	const merged = mergeStores(wrap({}), null);
	for (const key of ["tokens", "clientInformation", "codeVerifier", "discoveryState", "authorizationServerUrl"]) {
		assert.ok(key in merged, `missing ${key}`);
	}
});
