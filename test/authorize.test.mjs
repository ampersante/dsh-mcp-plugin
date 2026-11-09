/**
 * End-to-end test of tools/authorize.mjs against a local authorization server.
 * It drives the flow the way a browser would, without leaving this process.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { symlinkSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { installSecurityStub } from "./support/security.mjs";

const home = await mkdtemp(join(tmpdir(), "dsh-authorize-"));
process.env.DSH_HOME = home;
const authorizeModule = await import("../tools/authorize.mjs");
const { authorizeOne } = authorizeModule;
const { createOAuthProvider, hubFor } = await import("../oauth.js");

after(() => rm(home, { recursive: true, force: true }));

function listen(server) {
	return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}

async function freePort() {
	const server = createServer();
	const port = await listen(server);
	await new Promise((resolve) => server.close(resolve));
	return port;
}

/**
 * One server that plays resource, authorization server and browser consent.
 * The verifier received at /token must match the challenge sent to /authorize.
 */
async function fakeAuthorizationServer({ rejectExchange = false } = {}) {
	const state = { challenge: null, tokenRequests: 0, registered: 0 };
	const server = createServer((request, response) => {
		const url = new URL(request.url, `http://127.0.0.1:${server.address().port}`);
		const origin = `http://127.0.0.1:${server.address().port}`;
		const send = (status, body, headers = {}) => {
			response.writeHead(status, { "content-type": "application/json", ...headers });
			response.end(body === undefined ? "" : JSON.stringify(body));
		};

		if (url.pathname === "/mcp" && request.method === "POST") {
			response.writeHead(401, {
				"content-type": "application/json",
				"www-authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"`,
			});
			response.end("{}");
			return;
		}
		if (url.pathname === "/.well-known/oauth-protected-resource") {
			// Deliberately different from the endpoint path: the server names its audience.
			send(200, { resource: origin, authorization_servers: [origin] });
			return;
		}
		if (url.pathname === "/.well-known/oauth-authorization-server") {
			send(200, {
				issuer: origin,
				authorization_endpoint: `${origin}/authorize`,
				token_endpoint: `${origin}/token`,
				registration_endpoint: `${origin}/register`,
				code_challenge_methods_supported: ["S256"],
				grant_types_supported: ["authorization_code", "refresh_token"],
			});
			return;
		}
		if (url.pathname === "/register" && request.method === "POST") {
			let body = "";
			request.on("data", (chunk) => (body += chunk));
			request.on("end", () => {
				state.registered += 1;
				state.redirectUri = JSON.parse(body).redirect_uris[0];
				send(201, { client_id: "local-client", token_endpoint_auth_method: "none" });
			});
			return;
		}
		if (url.pathname === "/authorize") {
			state.challenge = url.searchParams.get("code_challenge");
			state.redirectUri = url.searchParams.get("redirect_uri");
			const redirect = new URL(url.searchParams.get("redirect_uri"));
			redirect.searchParams.set("code", "local-code");
			redirect.searchParams.set("state", url.searchParams.get("state"));
			response.writeHead(302, { location: redirect.href });
			response.end();
			return;
		}
		if (url.pathname === "/token" && request.method === "POST") {
			let body = "";
			request.on("data", (chunk) => (body += chunk));
			request.on("end", () => {
				state.tokenRequests += 1;
				if (rejectExchange) return send(400, { error: "invalid_grant" });
				const form = new URLSearchParams(body);
				const verifier = form.get("code_verifier") ?? "";
				const challenge = createHash("sha256").update(verifier).digest("base64url");
				if (form.get("code") !== "local-code") return send(400, { error: "invalid_grant" });
				if (challenge !== state.challenge) return send(400, { error: "invalid_grant", error_description: "verifier mismatch" });
				if (form.get("redirect_uri") !== state.redirectUri) return send(400, { error: "invalid_grant", error_description: "redirect mismatch" });
				send(200, {
					access_token: "local-access-token",
					token_type: "Bearer",
					expires_in: 3600,
					refresh_token: "local-refresh-token",
				});
			});
			return;
		}
		response.writeHead(404).end();
	});
	const port = await listen(server);
	return { server, port, origin: `http://127.0.0.1:${port}`, state };
}

function waitForLink(links) {
	return new Promise((resolve, reject) => {
		const started = Date.now();
		const tick = () => {
			if (links.length > 0) return resolve(links[0]);
			if (Date.now() - started > 5000) return reject(new Error("the helper never printed an authorization link"));
			setTimeout(tick, 10);
		};
		tick();
	});
}

test("completes the flow, stores a readable token and reuses it", async (t) => {
	// Every authorization test runs against the stub, never the real Keychain.
	const stub = installSecurityStub(t, { hard: true });
	const { server, origin, state } = await fakeAuthorizationServer();
	const hubPort = await freePort();
	const links = [];
	try {
		const flow = authorizeOne("local", `${origin}/mcp`, {
			port: hubPort,
			timeoutMs: 5000,
			force: false,
			log: (link) => links.push(link),
		});
		const link = await waitForLink(links);
		assert.match(link, /code_challenge_method=S256/, "the link must carry PKCE");
		assert.equal(new URL(link).searchParams.get("redirect_uri"), `http://127.0.0.1:${hubPort}/callback/local`);
		assert.equal(
			new URL(link).searchParams.get("resource"),
			origin,
			"the resource must be the audience the server advertises, not the endpoint URL",
		);

		// Act as the browser: consent, then follow the redirect to the callback.
		const consent = await fetch(link, { redirect: "manual" });
		assert.equal(consent.status, 302);
		const callback = await fetch(consent.headers.get("location"));
		assert.equal(callback.status, 200);

		const result = await flow;
		assert.equal(result.status, "authorized");
		assert.equal(state.tokenRequests, 1, "the code must be exchanged exactly once");

		const stored = await createOAuthProvider({
			serverName: "local",
			serverUrl: `${origin}/mcp`,
			oauth: { callbackPort: hubPort },
		}).tokens();
		assert.equal(stored.access_token, "local-access-token");
		assert.equal(stored.refresh_token, "local-refresh-token");

		// A4 guard: the flow must persist through the hard security stub.
		assert.ok(
			Object.keys(stub.readStore()).includes("dsh-mcp-oauth/local"),
			"the authorization must be written through the security stub, never the real Keychain",
		);

		const again = await authorizeOne("local", `${origin}/mcp`, {
			port: hubPort,
			timeoutMs: 5000,
			force: false,
			log: () => assert.fail("an authorized server must not print a new link"),
		});
		assert.equal(again.status, "already authorized");
		assert.equal(state.registered, 1, "the stored client registration must be reused");
	} finally {
		await new Promise((resolve) => server.close(resolve));
	}
});

test("reports a rejected exchange and keeps no token", async (t) => {
	installSecurityStub(t, { hard: true });
	const world = await fakeAuthorizationServer({ rejectExchange: true });
	const hubPort = await freePort();
	const links = [];
	try {
		const flow = authorizeOne("broken", `${world.origin}/mcp`, {
			port: hubPort,
			timeoutMs: 5000,
			force: false,
			log: (link) => links.push(link),
		});
		// Handle the rejection as soon as it can happen, not after the callback.
		const settled = flow.then(
			(value) => ({ failed: false, value }),
			(error) => ({ failed: true, error }),
		);
		const link = await waitForLink(links);
		const consent = await fetch(link, { redirect: "manual" });
		const callback = await fetch(consent.headers.get("location"));
		assert.equal(callback.status, 500, "the browser must be told the exchange failed");
		const outcome = await settled;
		assert.equal(outcome.failed, true, "the flow must not report success");
		assert.match(outcome.error.message, /invalid_grant/);

		const stored = await createOAuthProvider({
			serverName: "broken",
			serverUrl: `${world.origin}/mcp`,
			oauth: { callbackPort: hubPort },
		}).tokens();
		assert.equal(stored, undefined, "a failed exchange must not store a credential");
	} finally {
		await new Promise((resolve) => world.server.close(resolve));
	}
});

// ── A1–A3: busy port, symlinked CLI, terminal text ──────────────────────────

// A1: a busy callback port must be an error with a code, and no flow may be left pending.
test("A1: a busy callback port fails with EADDRINUSE and leaves nothing pending", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true });
	const world = await fakeAuthorizationServer();
	t.after(() => new Promise((resolve) => world.server.close(resolve)));
	const busy = createServer();
	const busyPort = await listen(busy);
	t.after(() => new Promise((resolve) => busy.close(resolve)));

	let failure;
	try {
		await authorizeOne("busy", `${world.origin}/mcp`, {
			port: busyPort,
			timeoutMs: 50,
			force: false,
			log: () => assert.fail("a busy port must not print a link"),
		});
	} catch (error) {
		failure = error;
	}
	// Record the result before teardown: a broken version leaves a flow behind.
	const hub = hubFor(busyPort);
	const pendingAfterFailure = hub.pending.size;
	for (const entry of hub.pending.values()) clearTimeout(entry.timer);
	hub.pending.clear();

	assert.ok(failure, "authorizeOne must reject a busy port");
	assert.equal(failure.code, "EADDRINUSE", "the error must carry the bind error code");
	assert.match(failure.message, /busy/, "the message must say the port is busy");
	assert.equal(pendingAfterFailure, 0, "a failed bind must leave no pending flow");
});

// A2: the CLI must start when reached through a symlink, not only by its real path.
test("A2: --help works through a symlink and exits 2", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true });
	const dir = await mkdtemp(join(tmpdir(), "dsh-authorize-link-"));
	t.after(() => rm(dir, { recursive: true, force: true }));
	const link = join(dir, "authorize-link.mjs");
	symlinkSync(fileURLToPath(new URL("../tools/authorize.mjs", import.meta.url)), link);

	const result = spawnSync(process.execPath, [link, "--help"], {
		encoding: "utf8",
		timeout: 15000,
		env: { ...process.env, DSH_HOME: home },
	});
	assert.equal(result.status, 2, `--help through a symlink must exit 2 (status=${result.status}): ${result.stderr}`);
	assert.match(result.stderr, /Usage:/, "the usage text must reach stderr");
});

// A3: server-provided text reaches the terminal, so control sequences are removed.
test("A3: sanitizeForTerminal drops escape controls and keeps newlines", { timeout: 20000 }, async (t) => {
	installSecurityStub(t, { hard: true });
	const sanitize = authorizeModule.sanitizeForTerminal;
	assert.equal(typeof sanitize, "function", "sanitizeForTerminal must be exported");

	const hostile = "safe\x1b[31mred\x1b[0m\x1b]8;;https://x\x07link\x1b]8;;\x07\x9b31mC1\nnext\ttab";
	const cleaned = sanitize(hostile);
	assert.ok(!cleaned.includes("\x1b"), "ESC must be removed");
	assert.ok(!/[\x00-\x08\x0e-\x1f\x7f-\x9f]/.test(cleaned), `every C0/C1 control must be removed, got ${JSON.stringify(cleaned)}`);
	assert.ok(cleaned.includes("\n"), "newlines must survive");
	assert.ok(cleaned.includes("\t"), "tabs must survive");
	assert.ok(cleaned.includes("safe") && cleaned.includes("next"), "printable text must survive");
});
