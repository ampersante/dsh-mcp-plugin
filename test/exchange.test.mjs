import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";

import { startMock } from "./support/mock-oauth.mjs";
import { installSecurityStub } from "./support/security.mjs";
import { ASAR, installResolveHook, resolveSdk } from "./support/sdk.mjs";

function freePort() {
	return new Promise((resolve, reject) => {
		const probe = createServer();
		probe.once("error", reject);
		probe.listen(0, "127.0.0.1", () => {
			const { port } = probe.address();
			probe.close(() => resolve(port));
		});
	});
}

/** Starts the SDK flow and captures the URL the provider was asked to open. */
async function beginAuthorization(t, { serverName, serverUrl }) {
	const callbackPort = await freePort();
	const provider = createOAuthProvider({ serverName, serverUrl, oauth: { enabled: true, callbackPort, openBrowser: false } });
	t.after(() => provider.hub.close());
	let authorizationUrl;
	const original = provider.redirectToAuthorization.bind(provider);
	provider.redirectToAuthorization = async (url) => {
		authorizationUrl = String(url);
		return await original(url);
	};
	const outcome = await auth(provider, { serverUrl });
	assert.equal(outcome, "REDIRECT");
	assert.ok(authorizationUrl, "the SDK did not hand an authorization URL to the provider");
	return { provider, authorizationUrl, callbackPort };
}

/** Plays the browser: the authorization endpoint redirects to the loopback callback. */
async function completeBrowser(authorizationUrl, provider) {
	const authorization = await fetch(authorizationUrl, { redirect: "manual" });
	assert.equal(authorization.status, 302);
	const callbackUrl = authorization.headers.get("location");
	assert.ok(callbackUrl, "the authorization endpoint did not redirect to the callback");
	assert.ok(callbackUrl.startsWith(`${provider.redirectUrl}?`), `unexpected callback URL ${callbackUrl}`);
	return await fetch(callbackUrl);
}

let createOAuthProvider;
let auth;
const sdk = await resolveSdk();

if (sdk === null) {
	test(`OAuth code exchange against the bundled MCP SDK (skip: ${ASAR} is not installed)`, {
		skip: `the DeepSeek Harness bundle is not installed at ${ASAR}`
	}, () => {});
} else {
	// Both must be in place before oauth.js is imported: the module reads them
	// at load time. The short timeout keeps a stuck callback from outliving the
	// test; the temporary home keeps the file store out of the real profile.
	const HOME = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-home-"));
	process.env.DSH_HOME = HOME;
	process.env.DSH_MCP_OAUTH_TIMEOUT_MS = "5000";
	after(() => rmSync(HOME, { recursive: true, force: true }));

	await installResolveHook(sdk.url);
	({ createOAuthProvider } = await import("../oauth.js"));
	({ auth } = await import(sdk.url));

	test("a code exchange stores the token and the PKCE verifier the mock checks", { timeout: 30000 }, async (t) => {
		installSecurityStub(t, { hard: true });
		const mock = await startMock(t);
		const serverName = `exchange-ok-${randomUUID().slice(0, 8)}`;
		const { provider, authorizationUrl, callbackPort } = await beginAuthorization(t, { serverName, serverUrl: mock.serverUrl });

		const callback = await completeBrowser(authorizationUrl, provider);
		assert.equal(callback.status, 200);
		assert.match(await callback.text(), /authorized/);

		const request = mock.tokenRequest;
		assert.ok(request, "the mock authorization server saw no token request");
		assert.equal(request.grant_type, "authorization_code");
		assert.equal(request.code, mock.authorizationCode);
		assert.equal(request.redirect_uri, provider.redirectUrl);
		assert.equal(request.resource, mock.serverUrl);
		assert.equal(request.client_id, mock.clientId);
		assert.equal(typeof request.code_verifier, "string");
		assert.ok(request.code_verifier.length > 0, "the token request carried an empty code_verifier");
		assert.equal(mock.verifierVerified, true, "the mock could not match the PKCE verifier to the S256 challenge");

		const saved = await provider.tokens();
		assert.ok(saved, "the provider stored no token after a successful exchange");
		assert.equal(saved.access_token, mock.accessToken);

		// A fresh provider must see the credential in the store, not in memory.
		const reloaded = createOAuthProvider({ serverName, serverUrl: mock.serverUrl, oauth: { enabled: true, callbackPort, openBrowser: false } });
		const restored = await reloaded.tokens();
		assert.ok(restored, "a fresh provider did not see the stored token");
		assert.equal(restored.access_token, mock.accessToken);

		const resource = await fetch(mock.serverUrl, { headers: { authorization: `Bearer ${saved.access_token}` } });
		assert.equal(resource.status, 200);
	});

	test("a rejected exchange answers 500 and stores no token", { timeout: 30000 }, async (t) => {
		const errors = t.mock.method(console, "error", () => {});
		installSecurityStub(t, { hard: true });
		const mock = await startMock(t, { corruptChallenge: true });
		const serverName = `exchange-reject-${randomUUID().slice(0, 8)}`;
		const { provider, authorizationUrl } = await beginAuthorization(t, { serverName, serverUrl: mock.serverUrl });

		const callback = await completeBrowser(authorizationUrl, provider);
		assert.equal(callback.status, 500);
		assert.match(await callback.text(), /token exchange failed/);
		assert.equal(await provider.tokens(), undefined);
		assert.equal(mock.verifierVerified, false);
		assert.ok(mock.tokenRequests.length > 0, "the token endpoint was never called");
		const logged = errors.mock.calls.map((call) => call.arguments.map(String).join(" "));
		assert.ok(logged.some((line) => line.includes("authorization failed")), `the failure was not logged: ${logged.join(" | ")}`);
	});

	test("a denied authorization shows the refusal and stores no token", { timeout: 30000 }, async (t) => {
		installSecurityStub(t, { hard: true });
		const mock = await startMock(t, { deny: true });
		const serverName = `exchange-deny-${randomUUID().slice(0, 8)}`;
		const { provider, authorizationUrl } = await beginAuthorization(t, { serverName, serverUrl: mock.serverUrl });

		const callback = await completeBrowser(authorizationUrl, provider);
		assert.equal(callback.status, 200);
		const page = await callback.text();
		assert.match(page, /denied/);
		assert.match(page, /access_denied/);
		assert.equal(await provider.tokens(), undefined);
		assert.equal(mock.requests.some((entry) => entry.path === "/token"), false, "a denied authorization must not reach the token endpoint");
	});
}
