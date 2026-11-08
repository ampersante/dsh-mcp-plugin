#!/usr/bin/env node
/**
 * Complete an MCP OAuth authorization from the terminal and store the result
 * where the plugin reads it.
 *
 *   node tools/authorize.mjs notion=https://mcp.notion.com/mcp
 *   node tools/authorize.mjs --port 8770 a=https://… b=https://…
 *
 * The listener runs in this process, so the redirect target is live from the
 * moment the link is printed and every failure is reported here. Credentials
 * go through the same store the plugin uses, so the next connection finds a
 * token and never opens a browser.
 */
import { createHash, randomBytes } from "node:crypto";
import { createOAuthProvider } from "../oauth.js";

const INITIALIZE = {
	jsonrpc: "2.0",
	id: 1,
	method: "initialize",
	params: {
		protocolVersion: "2025-06-18",
		capabilities: {},
		clientInfo: { name: "dsh-mcp-oauth", version: "1" },
	},
};

function base64url(buffer) {
	return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function escapeHtml(value) {
	return String(value).replace(/[&<>"']/g, (character) => `&#${character.charCodeAt(0)};`);
}

async function readJson(url, init) {
	const response = await fetch(url, {
		...init,
		headers: { accept: "application/json", ...(init?.headers ?? {}) },
	});
	const text = await response.text();
	let body = null;
	try {
		body = text ? JSON.parse(text) : null;
	} catch {}
	return { response, body, text };
}

/** Locate the authorization server the resource advertises. */
export async function discover(serverUrl) {
	const url = new URL(serverUrl);
	let metadataUrl = `${url.origin}/.well-known/oauth-protected-resource`;

	let probe;
	try {
		probe = await fetch(serverUrl, {
			method: "POST",
			headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
			body: JSON.stringify(INITIALIZE),
		});
	} catch (error) {
		throw new Error(`cannot reach ${serverUrl}: ${error.cause?.code ?? error.message}`);
	}
	if (probe.status !== 401) {
		throw new Error(`${serverUrl} answered ${probe.status}, expected 401 with a resource_metadata pointer`);
	}
	const advertised = /resource_metadata="([^"]+)"/i.exec(probe.headers.get("www-authenticate") ?? "");
	if (advertised) metadataUrl = advertised[1];

	const resource = await readJson(metadataUrl);
	if (!resource.body) throw new Error(`protected resource metadata at ${metadataUrl} is unreadable`);
	// The server decides its own audience; an endpoint URL is not always it.
	const resourceId = resource.body.resource ?? serverUrl;
	const issuer = resource.body.authorization_servers?.[0] ?? resourceId;
	const server = await authorizationServerMetadata(issuer);
	return { ...server, resource: resourceId };
}

async function authorizationServerMetadata(issuer) {
	const url = new URL(issuer);
	const path = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
	const candidates = [
		`${url.origin}/.well-known/oauth-authorization-server${path}`,
		`${url.origin}${path}/.well-known/oauth-authorization-server`,
		`${url.origin}/.well-known/openid-configuration${path}`,
	];
	for (const candidate of candidates) {
		const { response, body } = await readJson(candidate);
		if (response.ok && body?.authorization_endpoint && body?.token_endpoint) {
			if (!body.registration_endpoint) {
				throw new Error(`${issuer} does not offer client registration, so a standalone client cannot be created`);
			}
			return body;
		}
	}
	throw new Error(`no authorization server metadata found for ${issuer}`);
}

async function registerClient(provider, server) {
	const { response, body, text } = await readJson(server.registration_endpoint, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(provider.clientMetadata),
	});
	if (!response.ok || !body?.client_id) {
		throw new Error(`client registration was refused (${response.status}): ${text.slice(0, 200)}`);
	}
	return body;
}

async function exchange({ server, client, code, verifier, redirectUri, resource }) {
	const form = new URLSearchParams({
		grant_type: "authorization_code",
		code,
		redirect_uri: redirectUri,
		client_id: client.client_id,
		code_verifier: verifier,
		resource,
	});
	const headers = {
		"content-type": "application/x-www-form-urlencoded",
		accept: "application/json",
	};
	if (client.client_secret) {
		headers.authorization = `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString("base64")}`;
	}
	const { response, body, text } = await readJson(server.token_endpoint, {
		method: "POST",
		headers,
		body: form,
	});
	if (!response.ok || !body?.access_token) {
		const detail = body?.error ? `${body.error}${body.error_description ? ` — ${body.error_description}` : ""}` : text;
		throw new Error(`token exchange failed (${response.status}): ${String(detail).slice(0, 200)}`);
	}
	return body;
}

/** Run one authorization to completion. Logs the link, never a credential. */
export async function authorizeOne(name, serverUrl, { port, timeoutMs, force, log }) {
	const provider = createOAuthProvider({ serverName: name, serverUrl, oauth: { callbackPort: port } });
	const existing = await provider.tokens();
	if (existing?.access_token && !force) return { name, status: "already authorized" };

	const server = await discover(serverUrl);
	let client = await provider.clientInformation();
	let registered = false;
	if (!client?.client_id) {
		client = await registerClient(provider, server);
		await provider.saveClientInformation(client);
		registered = true;
	}

	const verifier = base64url(randomBytes(32));
	await provider.saveCodeVerifier(verifier);
	const challenge = base64url(createHash("sha256").update(verifier).digest());
	const state = base64url(randomBytes(16));

	const target = new URL(server.authorization_endpoint);
	target.searchParams.set("response_type", "code");
	target.searchParams.set("client_id", client.client_id);
	target.searchParams.set("redirect_uri", provider.redirectUrl);
	target.searchParams.set("state", state);
	target.searchParams.set("code_challenge", challenge);
	target.searchParams.set("code_challenge_method", "S256");
	target.searchParams.set("resource", server.resource);

	const { promise } = provider.hub.register(name, state, timeoutMs);
	await provider.hub.ensure();
	log(target.href);

	const { code, respond } = await promise;
	try {
		const tokens = await exchange({
			server,
			client,
			code,
			verifier,
			redirectUri: provider.redirectUrl,
			resource: server.resource,
		});
		await provider.saveTokens({
			access_token: tokens.access_token,
			token_type: tokens.token_type ?? "Bearer",
			...(tokens.expires_in ? { expires_in: tokens.expires_in } : {}),
			...(tokens.refresh_token ? { refresh_token: tokens.refresh_token } : {}),
			...(tokens.scope ? { scope: tokens.scope } : {}),
		});

		// The token has to be readable by a fresh provider: that is exactly what
		// the plugin builds on its next connection.
		const stored = await createOAuthProvider({ serverName: name, serverUrl, oauth: { callbackPort: port } }).tokens();
		if (stored?.access_token !== tokens.access_token) {
			throw new Error("the credential was written but cannot be read back");
		}

		respond?.(200, `<p><b>${escapeHtml(name)}</b>: connected.</p><p>You can close this tab.</p>`);
		return { name, status: "authorized", registered };
	} catch (error) {
		respond?.(500, `<p><b>${escapeHtml(name)}</b>: ${escapeHtml(error.message)}</p>`);
		throw error;
	}
}

function usage() {
	console.error(
		[
			"Usage: node tools/authorize.mjs [options] name=url [name=url …]",
			"",
			"  --port N       callback port, must equal oauth.callbackPort in the server config (default 8765)",
			"  --timeout N    minutes to wait for the browser sign-in (default 10)",
			"  --force        authorize again even when a token is already stored",
			"  --parallel     wait for every server at once so all links stay valid together",
			"",
			"Example: node tools/authorize.mjs --port 8770 notion=https://mcp.notion.com/mcp",
		].join("\n"),
	);
	process.exit(2);
}

async function main() {
	const options = { port: 8765, timeoutMs: 10 * 60 * 1000, force: false, parallel: false };
	const pairs = [];
	const args = process.argv.slice(2);
	for (let index = 0; index < args.length; index += 1) {
		const argument = args[index];
		if (argument === "--port") options.port = Number(args[(index += 1)]);
		else if (argument === "--timeout") options.timeoutMs = Number(args[(index += 1)]) * 60 * 1000;
		else if (argument === "--force") options.force = true;
		else if (argument === "--parallel") options.parallel = true;
		else if (argument === "--help" || argument === "-h") usage();
		else {
			const separator = argument.indexOf("=");
			if (separator < 1) usage();
			pairs.push([argument.slice(0, separator), argument.slice(separator + 1)]);
		}
	}
	if (pairs.length === 0) usage();
	if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
		console.error("--port must be a port number");
		process.exit(2);
	}

	const one = async ([name, url]) => {
		const result = await authorizeOne(name, url, {
			...options,
			log: (link) => console.log(`\n--- ${name} — open and sign in ---\n${link}\n`),
		});
		console.log(`${name}: ${result.status}`);
		return result;
	};

	let failures = 0;
	if (options.parallel) {
		const settled = await Promise.allSettled(pairs.map(one));
		for (const [index, outcome] of settled.entries()) {
			if (outcome.status === "rejected") {
				failures += 1;
				console.error(`${pairs[index][0]}: failed — ${outcome.reason.message}`);
			}
		}
	} else {
		for (const pair of pairs) {
			try {
				await one(pair);
			} catch (error) {
				failures += 1;
				console.error(`${pair[0]}: failed — ${error.message}`);
			}
		}
	}
	process.exit(failures === 0 ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
