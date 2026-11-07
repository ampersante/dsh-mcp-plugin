import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.DSH_HOME = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-test-"));
const { CallbackHub, createOAuthProvider } = await import("../oauth.js");

async function hubOn(t) {
	const hub = new CallbackHub(0);
	const server = await hub.ensure();
	t.after(() => hub.close());
	return { hub, port: server.address().port };
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

test("revoking credentials deletes the file copy as well", async () => {
	const provider = createOAuthProvider({ serverName: "revoke-me", serverUrl: "https://mcp.example/mcp", oauth: { enabled: true, callbackPort: 8799 } });
	await provider.saveTokens({ access_token: "secret", token_type: "Bearer" });
	assert.ok(await provider.tokens());
	await provider.invalidateCredentials("all");
	assert.equal(await provider.tokens(), undefined);
});

test("credentials issued for another resource are not reused", async () => {
	const a = createOAuthProvider({ serverName: "shared-name", serverUrl: "https://one.example/mcp", oauth: { enabled: true, callbackPort: 8798 } });
	await a.saveTokens({ access_token: "token-one", token_type: "Bearer" });
	const b = createOAuthProvider({ serverName: "shared-name", serverUrl: "https://two.example/mcp", oauth: { enabled: true, callbackPort: 8798 } });
	assert.equal(await b.tokens(), undefined);
});
