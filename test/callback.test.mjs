import test from "node:test";
import assert from "node:assert/strict";
import { CallbackHub, createOAuthProvider } from "../oauth.js";

async function startedHub(t) {
	const hub = new CallbackHub(0);
	const server = await hub.ensure();
	t.after(() => hub.close());
	return { hub, port: server.address().port };
}

const get = (port, path) => fetch(`http://127.0.0.1:${port}${path}`);

test("a matching state delivers the code and issuer, and the reply follows the exchange", async (t) => {
	const { hub, port } = await startedHub(t);
	const flow = hub.register("alpha", "s1");
	const pending = get(port, "/callback/alpha?code=c1&state=s1&iss=https%3A%2F%2Fas.example");
	const delivered = await flow.promise;
	assert.equal(delivered.code, "c1");
	assert.equal(delivered.iss, "https://as.example");
	delivered.respond(200, "ok");
	assert.equal((await pending).status, 200);
});

test("a wrong state answers 400 and leaves the flow pending", async (t) => {
	const { hub, port } = await startedHub(t);
	hub.register("beta", "right").promise.catch(() => {});
	const response = await get(port, "/callback/beta?code=c&state=wrong");
	assert.equal(response.status, 400);
	assert.equal(hub.pending.size, 1);
});

test("an unknown server answers 409 and an unknown path 404", async (t) => {
	const { hub, port } = await startedHub(t);
	assert.equal((await get(port, "/callback/ghost?code=c&state=s")).status, 409);
	assert.equal((await get(port, "/elsewhere")).status, 404);
});

test("a non-GET callback answers 405", async (t) => {
	const { hub, port } = await startedHub(t);
	const response = await fetch(`http://127.0.0.1:${port}/callback/alpha?code=c&state=s`, { method: "POST" });
	assert.equal(response.status, 405);
});

test("a denial answers 200 and rejects the flow with the reason", async (t) => {
	const { hub, port } = await startedHub(t);
	const flow = hub.register("gamma", "s2");
	const expectation = assert.rejects(flow.promise, /access_denied/);
	assert.equal((await get(port, "/callback/gamma?error=access_denied&state=s2")).status, 200);
	await expectation;
});

test("the listener closes once the last flow finishes", async (t) => {
	const { hub, port } = await startedHub(t);
	const flow = hub.register("delta", "s3");
	const pending = get(port, "/callback/delta?code=c&state=s3");
	const delivered = await flow.promise;
	delivered.respond(200, "ok");
	await pending;
	await new Promise((r) => setTimeout(r, 20));
	assert.equal(hub.server, null);
	await assert.rejects(get(port, "/callback/delta?code=c&state=s3"));
});

test("the provider exposes a stable loopback redirect and client metadata", () => {
	const provider = createOAuthProvider({ serverName: "eps", serverUrl: "https://mcp.example/mcp", oauth: { enabled: true, callbackPort: 8765 } });
	assert.equal(provider.redirectUrl, "http://127.0.0.1:8765/callback/eps");
	const metadata = provider.clientMetadata;
	assert.deepEqual(metadata.redirect_uris, [provider.redirectUrl]);
	assert.equal(metadata.token_endpoint_auth_method, "none");
	assert.ok(metadata.grant_types.includes("authorization_code"));
});
