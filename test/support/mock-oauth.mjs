/**
 * A minimal OAuth 2.1 authorization server and protected MCP resource, used to
 * drive the plugin's browser leg and code exchange without the network.
 *
 * The server advertises exactly what the SDK needs: protected resource
 * metadata, authorization server metadata, dynamic client registration, an
 * authorization endpoint that redirects to the loopback callback, and a token
 * endpoint that verifies the PKCE S256 challenge before issuing a token.
 */
import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";

const JSON_HEADERS = { "content-type": "application/json" };

function listen(server) {
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => {
			server.off("error", reject);
			resolve(server.address().port);
		});
	});
}

function close(server) {
	return new Promise((resolve) => {
		server.closeAllConnections?.();
		server.close(() => resolve());
	});
}

function send(response, status, body, headers = {}) {
	response.writeHead(status, { ...headers, ...JSON_HEADERS });
	response.end(JSON.stringify(body));
}

function redirect(response, location) {
	response.writeHead(302, { location });
	response.end();
}

async function readBody(request) {
	const chunks = [];
	for await (const chunk of request) chunks.push(chunk);
	return Buffer.concat(chunks).toString("utf8");
}

/** Verifies the PKCE verifier against the S256 challenge from the authorization request. */
function verifiesVerifier(challenge, verifier) {
	if (typeof challenge !== "string" || typeof verifier !== "string" || verifier.length === 0) return false;
	return createHash("sha256").update(verifier).digest("base64url") === challenge;
}

async function handleAuthorizationServer(request, response, state) {
	const url = new URL(request.url, "http://127.0.0.1");
	const path = url.pathname;
	if (request.method === "GET" && path === "/.well-known/oauth-authorization-server") {
		send(response, 200, {
			issuer: state.issuer,
			authorization_endpoint: `${state.issuer}/authorize`,
			token_endpoint: `${state.issuer}/token`,
			registration_endpoint: `${state.issuer}/register`,
			response_types_supported: ["code"],
			grant_types_supported: ["authorization_code", "refresh_token"],
			code_challenge_methods_supported: ["S256"],
			token_endpoint_auth_methods_supported: ["none"]
		});
		return;
	}
	if (request.method === "POST" && path === "/register") {
		const body = JSON.parse((await readBody(request)) || "{}");
		state.requests.push({ method: request.method, path, body });
		state.registration = body;
		if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
			send(response, 400, { error: "invalid_client_metadata", error_description: "redirect_uris is required" });
			return;
		}
		state.clientId = `mock-client-${randomUUID()}`;
		send(response, 201, {
			client_id: state.clientId,
			redirect_uris: body.redirect_uris,
			token_endpoint_auth_method: "none"
		});
		return;
	}
	if (request.method === "GET" && path === "/authorize") {
		const query = Object.fromEntries(url.searchParams);
		state.requests.push({ method: request.method, path, body: query });
		state.authorizationRequest = query;
		const redirectUri = query.redirect_uri;
		if (!redirectUri) {
			send(response, 400, { error: "invalid_request", error_description: "redirect_uri is required" });
			return;
		}
		if (state.options.deny) {
			const target = new URL(redirectUri);
			target.searchParams.set("error", "access_denied");
			target.searchParams.set("error_description", "the user refused the authorization");
			if (query.state) target.searchParams.set("state", query.state);
			redirect(response, target.href);
			return;
		}
		if (query.response_type !== "code" || query.code_challenge_method !== "S256" || !query.code_challenge) {
			const target = new URL(redirectUri);
			target.searchParams.set("error", "invalid_request");
			if (query.state) target.searchParams.set("state", query.state);
			redirect(response, target.href);
			return;
		}
		const code = `mock-code-${randomUUID()}`;
		state.authorizationCode = code;
		state.codes.set(code, {
			challenge: state.options.corruptChallenge ? `corrupted-${query.code_challenge}` : query.code_challenge,
			redirectUri,
			clientId: query.client_id,
			resource: query.resource
		});
		const target = new URL(redirectUri);
		target.searchParams.set("code", code);
		if (query.state) target.searchParams.set("state", query.state);
		redirect(response, target.href);
		return;
	}
	if (request.method === "POST" && path === "/token") {
		const body = Object.fromEntries(new URLSearchParams(await readBody(request)));
		state.requests.push({ method: request.method, path, body });
		state.tokenRequest = body;
		state.tokenRequests.push(body);
		const grant = state.codes.get(body.code);
		const verified = grant !== undefined && body.grant_type === "authorization_code" && verifiesVerifier(grant.challenge, body.code_verifier);
		state.verifierVerified = verified;
		if (!verified) {
			send(response, 400, { error: "invalid_grant", error_description: "the authorization code or code verifier is not valid" });
			return;
		}
		if (grant.redirectUri !== body.redirect_uri) {
			send(response, 400, { error: "invalid_grant", error_description: "redirect_uri does not match the authorization request" });
			return;
		}
		state.codes.delete(body.code);
		state.accessToken = `mock-access-${randomUUID()}`;
		send(response, 200, {
			access_token: state.accessToken,
			token_type: "Bearer",
			expires_in: 3600
		});
		return;
	}
	send(response, 404, { error: "not_found" });
}

async function handleResourceServer(request, response, state) {
	const url = new URL(request.url, "http://127.0.0.1");
	const path = url.pathname;
	if (request.method === "GET" && (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp")) {
		send(response, 200, {
			resource: state.serverUrl,
			authorization_servers: [state.issuer],
			scopes_supported: ["read"]
		});
		return;
	}
	if (request.method === "GET" && path === "/mcp") {
		const authorization = request.headers.authorization;
		if (authorization !== `Bearer ${state.accessToken}`) {
			response.writeHead(401, {
				"www-authenticate": `Bearer resource_metadata="${state.resourceMetadataUrl}"`,
				"content-type": "application/json"
			});
			response.end(JSON.stringify({ error: "unauthorized" }));
			return;
		}
		send(response, 200, { ok: true });
		return;
	}
	send(response, 404, { error: "not_found" });
}

/**
 * Starts both servers on loopback ports and closes them when the test ends.
 *
 * Options: `deny: true` makes the authorization endpoint refuse the request
 * with `error=access_denied`; `corruptChallenge: true` stores a challenge the
 * real verifier cannot match, so the token endpoint rejects the exchange.
 */
export async function startMock(t, options = {}) {
	const state = {
		options,
		issuer: "",
		serverUrl: "",
		resourceMetadataUrl: "",
		requests: [],
		tokenRequest: null,
		tokenRequests: [],
		registration: null,
		authorizationRequest: null,
		authorizationCode: null,
		clientId: null,
		accessToken: null,
		verifierVerified: false,
		codes: new Map()
	};
	const authorizationServer = createServer((request, response) => {
		handleAuthorizationServer(request, response, state).catch((error) => {
			response.writeHead(500, { ...JSON_HEADERS });
			response.end(JSON.stringify({ error: "mock_failure", error_description: String(error) }));
		});
	});
	const resourceServer = createServer((request, response) => {
		handleResourceServer(request, response, state).catch((error) => {
			response.writeHead(500, { ...JSON_HEADERS });
			response.end(JSON.stringify({ error: "mock_failure", error_description: String(error) }));
		});
	});
	const authorizationPort = await listen(authorizationServer);
	let resourcePort;
	try {
		resourcePort = await listen(resourceServer);
	} catch (error) {
		await close(authorizationServer);
		throw error;
	}
	state.issuer = `http://127.0.0.1:${authorizationPort}`;
	state.serverUrl = `http://127.0.0.1:${resourcePort}/mcp`;
	state.resourceMetadataUrl = `http://127.0.0.1:${resourcePort}/.well-known/oauth-protected-resource/mcp`;
	t.after(async () => {
		await Promise.all([close(authorizationServer), close(resourceServer)]);
	});
	return state;
}
