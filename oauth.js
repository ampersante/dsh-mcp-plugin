/**
 * OAuth credential provider for MCP servers.
 *
 * The SDK owns the protocol (discovery, dynamic client registration, PKCE,
 * exchange, refresh, step-up). This module stores credentials and runs the
 * browser leg, so the harness gets native tools without a bridge process.
 *
 * Invariants:
 * - the callback listener exists only while an authorization is pending and is
 *   closed when the last flow finishes;
 * - one authorization per server at a time; a flow already under way is reused,
 *   never restarted, and never opens a second browser window;
 * - the port is reserved before the browser opens, so a busy port is an error
 *   rather than a dead end after consent;
 * - the callback accepts GET only, from loopback, with a constant-time `state`
 *   check, a bounded query, escaped markup, and `no-store`;
 * - credentials live in the Keychain, with a `0600` file fallback; writes merge
 *   under a queue so a stale provider cannot erase a token written by another;
 * - revoking a credential removes every copy, not just the preferred one.
 */
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

const KEYCHAIN_SERVICE = "dsh-mcp-oauth";
const DEFAULT_CALLBACK_PORT = 8765;
const MAX_QUERY_BYTES = 8192;
const LOG_DEDUPE_MS = 10 * 60 * 1000;
const SECURITY_TIMEOUT_MS = 15000;
// `security -i` reads stdin line by line and silently cuts a line past 4096
// bytes while still exiting 0, so a longer command goes straight to the file.
const KEYCHAIN_COMMAND_LIMIT = 4000;
const STATE_PATH = join(process.env.DSH_HOME ?? join(homedir(), ".dsh"), "mcp-oauth");

function timeoutMs() {
	const raw = Number(process.env.DSH_MCP_OAUTH_TIMEOUT_MS ?? 10 * 60 * 1000);
	return Number.isFinite(raw) && raw > 0 ? raw : 10 * 60 * 1000;
}

const EMPTY_STATE = () => ({
	clientInformation: null,
	tokens: null,
	codeVerifier: null,
	discoveryState: null,
	authorizationServerUrl: null,
	resourceUrl: null
});

/** Loaded on demand so the module can be imported (and tested) without the SDK. */
let sdkAuth;
async function loadAuth() {
	sdkAuth ??= (await import("@modelcontextprotocol/client")).auth;
	return sdkAuth;
}

/**
 * Module state hangs off a global symbol: the harness reloads plugin modules on
 * configuration changes, and a pending authorization must survive that reload.
 */
const REGISTRY = Symbol.for("dsh-mcp-oauth.registry");
const registry = globalThis[REGISTRY] ??= {
	logged: new Map(),
	flows: new Map(),
	attempts: new Map(),
	blocked: new Map(),
	hubs: new Map(),
	writeQueues: new Map()
};

function log(key, message) {
	const now = Date.now();
	const previous = registry.logged.get(key);
	if (previous !== void 0 && now - previous < LOG_DEDUPE_MS) return;
	registry.logged.set(key, now);
	console.error(`[dsh-mcp-oauth] ${message}`);
}

/** Run a helper with a deadline; a hung `security` must not hang the plugin. */
function run(command, args, input) {
	return new Promise((resolve, reject) => {
		const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		let settled = false;
		const finish = (fn, value) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			fn(value);
		};
		const timer = setTimeout(() => {
			child.kill("SIGKILL");
			finish(reject, new Error(`${command} timed out after ${SECURITY_TIMEOUT_MS}ms`));
		}, SECURITY_TIMEOUT_MS);
		timer.unref?.();
		child.stdout.on("data", (chunk) => stdout += chunk);
		child.stderr.on("data", (chunk) => stderr += chunk);
		child.on("error", (error) => finish(reject, error));
		child.on("close", (code) => code === 0 ? finish(resolve, stdout) : finish(reject, new Error(`${command} exited ${code}: ${stderr.trim()}`)));
		child.stdin.on("error", () => {});
		child.stdin.end(input ?? "");
	});
}

async function readKeychainItem(account) {
	try {
		const stdout = await run("security", ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"]);
		const encoded = stdout.trim();
		return encoded ? Buffer.from(encoded, "base64").toString("utf8") : null;
	} catch {
		return null;
	}
}

async function readStores(account) {
	const keychain = await readKeychainItem(account);
	let file = null;
	try {
		file = await readFile(join(STATE_PATH, `${account}.json`), "utf8");
	} catch {}
	return { keychain, file };
}

/**
 * Both stores are read because they can hold different fields: the Keychain may
 * keep client registration from an abandoned attempt while the file keeps the
 * token a later authorization produced. The Keychain wins where it has a value;
 * the file fills the gaps.
 */
export function mergeStores(keychain, file) {
	const parse = (raw) => {
		if (!raw) return null;
		try {
			return JSON.parse(raw);
		} catch {
			return null;
		}
	};
	const preferred = parse(keychain);
	const secondary = parse(file);
	if (!preferred) return secondary ? { ...EMPTY_STATE(), ...secondary } : null;
	if (!secondary) return { ...EMPTY_STATE(), ...preferred };
	const merged = { ...EMPTY_STATE(), ...preferred };
	for (const key of Object.keys(EMPTY_STATE())) {
		const value = merged[key];
		if (value === null || value === void 0) merged[key] = secondary[key] ?? null;
	}
	return merged;
}

/** Remove the Keychain entry only; the file store is a separate copy. */
async function deleteKeychainItem(account) {
	await run("security", ["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account]).catch(() => {});
}

/** Replace the file copy atomically, readable by its owner only. */
async function writeFileStore(account, value) {
	await mkdir(STATE_PATH, { recursive: true, mode: 0o700 });
	const target = join(STATE_PATH, `${account}.json`);
	const temporary = `${target}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
	try {
		await writeFile(temporary, value, { mode: 0o600 });
		await chmod(temporary, 0o600);
		await rename(temporary, target);
	} finally {
		await rm(temporary, { force: true }).catch(() => {});
	}
	return target;
}

async function writeSecret(account, value) {
	const encoded = Buffer.from(value, "utf8").toString("base64");
	const command = `add-generic-password -U -s ${KEYCHAIN_SERVICE} -a ${account} -w ${encoded}`;
	if (Buffer.byteLength(command, "utf8") >= KEYCHAIN_COMMAND_LIMIT) {
		const target = await writeFileStore(account, value);
		// A stale Keychain copy would win over the file on the next read.
		await deleteKeychainItem(account);
		log(`store:${account}`, `${account}: credential does not fit one security command line; kept at ${target} with mode 0600`);
		return "file";
	}
	try {
		await run("security", ["-i"], `${command}\n`);
	} catch (error) {
		const target = await writeFileStore(account, value);
		log(`store:${account}`, `${account}: Keychain unavailable (${String(error).split("\n")[0]}); credentials kept at ${target} with mode 0600`);
		return "file";
	}
	const stored = await readKeychainItem(account);
	if (stored !== value) {
		await deleteKeychainItem(account);
		const target = await writeFileStore(account, value);
		log(`store:${account}`, `${account}: Keychain returned a different value after the write; removed that entry and kept credentials at ${target} with mode 0600`);
		return "file";
	}
	return "keychain";
}

/** Revocation must remove every copy: a surviving file would resurrect the secret. */
async function clearSecret(account) {
	const path = join(STATE_PATH, `${account}.json`);
	await rm(path, { force: true }).catch(() => {});
	await deleteKeychainItem(account);
}

/** Serialize writes per account so two concurrent saves cannot interleave. */
function queueWrite(account, task) {
	const previous = registry.writeQueues.get(account) ?? Promise.resolve();
	const next = previous.then(task, task);
	registry.writeQueues.set(account, next.catch(() => {}));
	return next;
}

function equalState(expected, received) {
	if (typeof expected !== "string" || typeof received !== "string") return false;
	const a = Buffer.from(expected);
	const b = Buffer.from(received);
	return a.length === b.length && timingSafeEqual(a, b);
}

function escapeHtml(value) {
	return String(value).replace(/[&<>"']/g, (character) => ({
		"&": "&amp;",
		"<": "&lt;",
		">": "&gt;",
		'"': "&quot;",
		"'": "&#39;"
	})[character]);
}

/**
 * Manual mode leaves the one-shot authorization link in the state directory so
 * a person can open it in the browser where the service is already signed in.
 */
async function writeAuthorizeLink(account, href) {
	try {
		await mkdir(STATE_PATH, { recursive: true, mode: 0o700 });
		const path = join(STATE_PATH, `${account}.authorize.txt`);
		await writeFile(path, `${href}\n`, { mode: 0o600 });
		await chmod(path, 0o600);
	} catch (error) {
		log(`manual:${account}`, `${account}: could not write the authorization link (${String(error.message ?? error)})`);
	}
}

/** The callback listener. It serves while any flow is pending, then closes. */
export class CallbackHub {
	constructor(port) {
		this.port = port;
		this.server = null;
		this.binding = null;
		this.error = null;
		this.pending = new Map();
	}

	async ensure() {
		if (this.server) return this.server;
		if (this.binding) return this.binding;
		this.error = null;
		this.binding = new Promise((resolve, reject) => {
			const server = createServer((request, response) => this.#handle(request, response));
			server.on("error", (error) => {
				const failure = error.code === "EADDRINUSE"
					? new Error(`callback port ${this.port} is busy — another DSH window or a stale process holds it; close it or set a different oauth.callbackPort for this server`)
					: error;
				this.error = failure;
				this.server = null;
				this.binding = null;
				reject(failure);
			});
			server.listen(this.port, "127.0.0.1", () => {
				this.server = server;
				resolve(server);
			});
		});
		return this.binding;
	}

	releaseIfIdle() {
		if (this.pending.size > 0) return;
		const server = this.server;
		this.server = null;
		this.binding = null;
		if (!server) return;
		server.closeAllConnections?.();
		server.close(() => {});
	}

	/** Stop the listener and reject everything still waiting (reload, tests). */
	async close() {
		for (const entry of this.pending.values()) {
			clearTimeout(entry.timer);
			entry.reject?.(new Error("callback listener closed"));
		}
		this.pending.clear();
		const server = this.server;
		this.server = null;
		this.binding = null;
		if (!server) return;
		server.closeAllConnections?.();
		await new Promise((resolve) => server.close(resolve));
	}

	/**
	 * A second registration for the same server would silently orphan the first
	 * timer and its promise, so it is refused instead.
	 */
	register(serverName, state, timeout = timeoutMs()) {
		if (this.pending.has(serverName)) throw new Error(`an authorization for ${serverName} is already pending`);
		let entry;
		const promise = new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(serverName);
				entry.respond?.(504, `<p><b>${escapeHtml(serverName)}</b>: authorization timed out. Close this tab and try again from DeepSeek Harness.</p>`);
				this.releaseIfIdle();
				reject(new Error(`authorization timed out — no browser callback within ${Math.round(timeout / 60000)} minutes`));
			}, timeout);
			timer.unref?.();
			entry = { state, resolve, reject, timer, respond: null };
			this.pending.set(serverName, entry);
		});
		return { promise };
	}

	#handle(request, response) {
		let done = false;
		const reply = (status, text, release = false) => {
			if (done) return;
			done = true;
			response.writeHead(status, {
				"content-type": "text/html; charset=utf-8",
				"cache-control": "no-store",
				"referrer-policy": "no-referrer",
				connection: "close"
			});
			response.end(`<!doctype html><meta charset="utf-8"><title>DeepSeek Harness</title><body style="font:15px -apple-system,system-ui;padding:2.5rem;line-height:1.5">${text}</body>`);
			if (release) setTimeout(() => this.releaseIfIdle(), 0);
		};

		if (request.method !== "GET") {
			reply(405, "Method not allowed.");
			return;
		}
		const raw = request.url ?? "/";
		if (raw.length > MAX_QUERY_BYTES) {
			reply(414, "Request too large.");
			return;
		}
		let url;
		try {
			url = new URL(raw, `http://127.0.0.1:${this.port}`);
		} catch {
			reply(400, "Malformed request.");
			return;
		}
		const match = /^\/callback\/([^/]+)$/.exec(url.pathname);
		if (!match) {
			reply(404, "Not found.");
			return;
		}
		let serverName;
		try {
			serverName = decodeURIComponent(match[1]);
		} catch {
			reply(400, "Malformed callback path.");
			return;
		}
		const entry = this.pending.get(serverName);
		if (!entry) {
			reply(409, `<p><b>${escapeHtml(serverName)}</b>: no authorization is pending.</p><p>Start the connection again from DeepSeek Harness.</p>`);
			return;
		}
		const error = url.searchParams.get("error");
		const code = url.searchParams.get("code");
		if (!equalState(entry.state, url.searchParams.get("state"))) {
			reply(400, `<p><b>${escapeHtml(serverName)}</b>: state mismatch, request rejected.</p>`);
			return;
		}
		clearTimeout(entry.timer);
		this.pending.delete(serverName);
		if (error) {
			const description = url.searchParams.get("error_description");
			reply(200, `<p><b>${escapeHtml(serverName)}</b>: authorization was denied (${escapeHtml(error)}).</p>`, true);
			entry.reject(new Error(`authorization denied: ${error}${description ? ` — ${description}` : ""}`));
			return;
		}
		if (!code) {
			reply(400, `<p><b>${escapeHtml(serverName)}</b>: callback carried no code.</p>`);
			entry.reject(new Error("callback carried no authorization code"));
			return;
		}
		// The answer waits for the exchange: a failed exchange must not look like success.
		entry.respond = (status, text) => reply(status, text, true);
		entry.resolve({ code, iss: url.searchParams.get("iss") ?? void 0, respond: entry.respond });
	}
}

export function hubFor(port) {
	const existing = registry.hubs.get(port);
	if (existing) return existing;
	const hub = new CallbackHub(port);
	registry.hubs.set(port, hub);
	return hub;
}

const RETRY_COOLDOWN_MS = 5 * 60 * 1000;

/** At most two windows per server per half hour, and none during a cooldown. */
function allowBrowser(serverName) {
	const now = Date.now();
	const blockedUntil = registry.blocked.get(serverName) ?? 0;
	if (now < blockedUntil) {
		log(`blocked:${serverName}`, `${serverName}: last authorization did not complete; not opening another browser window for ${Math.ceil((blockedUntil - now) / 60000)} more minutes — restart DeepSeek Harness to retry now`);
		return false;
	}
	const recent = (registry.attempts.get(serverName) ?? []).filter((at) => now - at < 30 * 60 * 1000);
	if (recent.length >= 2) {
		log(`limit:${serverName}`, `${serverName}: authorization was already offered twice in the last 30 minutes; not opening another browser window — restart DeepSeek Harness when you are ready to authorize`);
		return false;
	}
	recent.push(now);
	registry.attempts.set(serverName, recent);
	return true;
}

export function createOAuthProvider({ serverName, serverUrl, oauth }) {
	const port = Number(oauth?.callbackPort ?? DEFAULT_CALLBACK_PORT);
	return new KeychainOAuthProvider({ serverName, serverUrl, oauth, hub: hubFor(port) });
}

class KeychainOAuthProvider {
	constructor({ serverName, serverUrl, oauth, hub }) {
		this.serverName = serverName;
		this.serverUrl = serverUrl;
		this.oauth = oauth;
		this.hub = hub;
		this.store = null;
		this.dirty = new Set();
	}

	async load() {
		if (this.store) return this.store;
		const { keychain, file } = await readStores(this.serverName);
		const merged = mergeStores(keychain, file);
		let state = merged ?? EMPTY_STATE();
		// A credential issued for another resource is never reused.
		if (state.resourceUrl && state.resourceUrl !== this.serverUrl) {
			log(`resource:${this.serverName}`, `${this.serverName}: stored credential belongs to ${state.resourceUrl}, ignoring it for ${this.serverUrl}`);
			state = EMPTY_STATE();
		}
		// A client registration bound to another redirect URI cannot be completed.
		const client = state.clientInformation;
		if (client?.redirect_uris && Array.isArray(client.redirect_uris) && !client.redirect_uris.includes(this.redirectUrl)) {
			log(`client:${this.serverName}`, `${this.serverName}: stored client registration targets another redirect URI, registering again`);
			state.clientInformation = null;
			this.dirty.add("clientInformation");
		}
		this.store = state;
		return this.store;
	}

	/**
	 * Read-merge-write under a per-account queue: only the fields this provider
	 * changed are applied, so a reconnect that holds a stale snapshot cannot
	 * erase a token another provider just stored.
	 */
	async persist() {
		const changed = [...this.dirty];
		if (changed.length === 0) return;
		const values = Object.fromEntries(changed.map((key) => [key, this.store[key]]));
		this.dirty.clear();
		await queueWrite(this.serverName, async () => {
			const latest = mergeStores(...Object.values(await readStores(this.serverName))) ?? EMPTY_STATE();
			for (const [key, value] of Object.entries(values)) latest[key] = value;
			latest.resourceUrl = this.serverUrl;
			await writeSecret(this.serverName, JSON.stringify(latest));
			this.store = latest;
		});
	}

	get redirectUrl() {
		return `http://127.0.0.1:${this.hub.port}/callback/${encodeURIComponent(this.serverName)}`;
	}

	get clientMetadata() {
		const metadata = {
			client_name: "DeepSeek Harness",
			redirect_uris: [this.redirectUrl],
			grant_types: ["authorization_code", "refresh_token"],
			response_types: ["code"],
			token_endpoint_auth_method: this.oauth.clientSecret ? "client_secret_basic" : "none"
		};
		if (this.oauth.scopes) metadata.scope = this.oauth.scopes;
		return metadata;
	}

	async clientInformation() {
		const state = await this.load();
		if (state.clientInformation) return state.clientInformation;
		if (this.oauth.clientId) {
			return {
				client_id: this.oauth.clientId,
				...(this.oauth.clientSecret ? { client_secret: this.oauth.clientSecret } : {})
			};
		}
		return void 0;
	}

	async saveClientInformation(info) {
		await this.load();
		this.store.clientInformation = info;
		this.dirty.add("clientInformation");
		await this.persist();
	}

	async tokens() {
		return (await this.load()).tokens ?? void 0;
	}

	async saveTokens(tokens) {
		await this.load();
		this.store.tokens = tokens;
		this.dirty.add("tokens");
		await this.persist();
		log(`token:${this.serverName}`, `${this.serverName}: access token stored (${tokens.token_type ?? "bearer"})`);
	}

	async saveCodeVerifier(codeVerifier) {
		await this.load();
		this.store.codeVerifier = codeVerifier;
		this.dirty.add("codeVerifier");
		await this.persist();
	}

	async codeVerifier() {
		return (await this.load()).codeVerifier;
	}

	async discoveryState() {
		return (await this.load()).discoveryState ?? void 0;
	}

	async saveDiscoveryState(discoveryState) {
		await this.load();
		this.store.discoveryState = discoveryState;
		this.dirty.add("discoveryState");
		await this.persist();
	}

	async saveAuthorizationServerUrl(url) {
		await this.load();
		this.store.authorizationServerUrl = url;
		this.dirty.add("authorizationServerUrl");
		await this.persist();
	}

	async invalidateCredentials(scope) {
		await this.load();
		if (scope === "all" || scope === "tokens") this.store.tokens = null;
		if (scope === "all" || scope === "client") this.store.clientInformation = null;
		if (scope === "all") {
			this.store.codeVerifier = null;
			this.store.discoveryState = null;
		}
		await queueWrite(this.serverName, () => clearSecret(this.serverName));
		this.store = EMPTY_STATE();
		this.dirty.clear();
		log(`invalidate:${this.serverName}`, `${this.serverName}: credentials cleared from every store (${scope})`);
	}

	async state() {
		return randomBytes(24).toString("base64url");
	}

	/**
	 * The SDK awaits this call, so a busy port surfaces before the browser opens.
	 * The state comes from the authorization URL itself, so a concurrent step-up
	 * cannot leave the browser holding a value the listener never learned.
	 */
	async redirectToAuthorization(url) {
		if (!/^https:$/.test(url.protocol) && url.hostname !== "127.0.0.1" && url.hostname !== "localhost") {
			log(`scheme:${this.serverName}`, `${this.serverName}: refusing to open a non-HTTPS authorization URL`);
			return;
		}
		if (registry.flows.has(this.serverName)) {
			log(`pending:${this.serverName}`, `${this.serverName}: authorization is already open in the browser; finish it there`);
			return;
		}
		const state = url.searchParams.get("state") ?? randomBytes(24).toString("base64url");
		registry.flows.set(this.serverName, true);
		try {
			this.hub.releaseIfIdle();
			await this.hub.ensure();
		} catch (error) {
			registry.flows.delete(this.serverName);
			log(`port:${this.hub.port}`, `${this.serverName}: ${String(error.message ?? error)}`);
			return;
		}
		const manual = this.oauth.openBrowser === false;
		if (!manual && !allowBrowser(this.serverName)) {
			registry.flows.delete(this.serverName);
			return;
		}
		let flow;
		try {
			flow = this.hub.register(this.serverName, state);
		} catch (error) {
			registry.flows.delete(this.serverName);
			log(`pending:${this.serverName}`, `${this.serverName}: ${String(error.message ?? error)}`);
			return;
		}
		log(`authorize:${this.serverName}`, `${this.serverName}: authorize at ${url.href}`);
		if (manual) await writeAuthorizeLink(this.serverName, url.href);
		if (!manual) spawn("open", [url.href], { stdio: "ignore", detached: true }).unref();
		flow.promise
			.then(async ({ code, iss, respond }) => {
				try {
					const auth = await loadAuth();
					const outcome = await auth(this, {
						serverUrl: this.serverUrl,
						authorizationCode: code,
						...(iss ? { iss } : {})
					});
					respond(200, `<p><b>${escapeHtml(this.serverName)}</b>: ${outcome === "AUTHORIZED" ? "authorized. You can close this tab." : `${escapeHtml(outcome)}. Check the DeepSeek Harness log.`}</p>`);
					log(`result:${this.serverName}`, `${this.serverName}: authorization ${outcome}`);
				} catch (error) {
					respond(500, `<p><b>${escapeHtml(this.serverName)}</b>: the token exchange failed — see the DeepSeek Harness log.</p>`);
					registry.blocked.set(this.serverName, Date.now() + RETRY_COOLDOWN_MS);
					log(`failed:${this.serverName}`, `${this.serverName}: authorization failed: ${String(error.message ?? error)}; no automatic retry for 5 minutes`);
				}
			})
			.catch((error) => {
				registry.blocked.set(this.serverName, Date.now() + RETRY_COOLDOWN_MS);
				log(`failed:${this.serverName}`, `${this.serverName}: authorization failed: ${String(error.message ?? error)}; no automatic retry for 5 minutes`);
			})
			.finally(() => {
				registry.flows.delete(this.serverName);
				void rm(join(STATE_PATH, `${this.serverName}.authorize.txt`), { force: true }).catch(() => {});
			});
	}
}
