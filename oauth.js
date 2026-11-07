/**
 * OAuth credential provider for MCP servers.
 *
 * The SDK owns the protocol (discovery, dynamic client registration, PKCE,
 * exchange, refresh, step-up). This module stores credentials and runs the
 * browser leg, so the harness gets native tools without a bridge process.
 *
 * Invariants:
 * - the callback listener exists only while an authorization is pending and is
 *   closed the moment the last flow finishes, so no port stays open;
 * - one authorization per server at a time: reconnects reuse the pending flow
 *   and never open a second browser window;
 * - the port is reserved before the browser opens, so a busy port is an error
 *   rather than a dead end after consent;
 * - the callback accepts GET only, from loopback, with a constant-time `state`
 *   check and a bounded query, and answers with `no-store`;
 * - credentials live in the Keychain, with a `0600` file fallback when the
 *   Keychain is unavailable (headless launch, locked keychain, sandboxed app).
 */
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, rename, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
/** Loaded on demand so the module can be imported (and tested) without the SDK. */
let sdkAuth;
async function loadAuth() {
	sdkAuth ??= (await import("@modelcontextprotocol/client")).auth;
	return sdkAuth;
}

const KEYCHAIN_SERVICE = "dsh-mcp-oauth";
const DEFAULT_CALLBACK_PORT = 8765;
const CALLBACK_TIMEOUT_MS = Number(process.env.DSH_MCP_OAUTH_TIMEOUT_MS ?? 10 * 60 * 1000);
const MAX_QUERY_BYTES = 8192;
const LOG_DEDUPE_MS = 10 * 60 * 1000;
const STATE_PATH = join(process.env.DSH_HOME ?? join(homedir(), ".dsh"), "mcp-oauth");

const EMPTY_STATE = () => ({
	clientInformation: null,
	tokens: null,
	codeVerifier: null,
	discoveryState: null,
	authorizationServerUrl: null
});

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

function run(command, args, input) {
	return new Promise((resolve, reject) => {
		const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => stdout += chunk);
		child.stderr.on("data", (chunk) => stderr += chunk);
		child.on("error", reject);
		child.on("close", (code) => code === 0 ? resolve(stdout) : reject(new Error(`${command} exited ${code}: ${stderr.trim()}`)));
		child.stdin.on("error", () => {});
		child.stdin.end(input ?? "");
	});
}

async function readStores(account) {
	let keychain = null;
	try {
		const stdout = await run("security", ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"]);
		const encoded = stdout.trim();
		if (encoded) keychain = Buffer.from(encoded, "base64").toString("utf8");
	} catch {}
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

async function writeSecret(account, value) {
	const encoded = Buffer.from(value, "utf8").toString("base64");
	try {
		await run("security", ["-i"], `add-generic-password -U -s ${KEYCHAIN_SERVICE} -a ${account} -w ${encoded}\n`);
		return;
	} catch (error) {
		await mkdir(STATE_PATH, { recursive: true, mode: 0o700 });
		const target = join(STATE_PATH, `${account}.json`);
		const temporary = `${target}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
		await writeFile(temporary, value, { mode: 0o600 });
		await chmod(temporary, 0o600);
		await rename(temporary, target);
		log(`store:${account}`, `${account}: Keychain unavailable (${String(error).split("\n")[0]}); credentials kept at ${target} with mode 0600`);
	}
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

/**
 * The callback listener. It binds on the first pending authorization, keeps
 * serving while any flow is pending, and closes when the last one finishes.
 */
export class CallbackHub {
	constructor(port) {
		this.port = port;
		this.server = null;
		this.binding = null;
		this.error = null;
		this.pending = new Map();
	}

	async ensure() {
		if (this.error) throw this.error;
		if (this.server) return this.server;
		if (this.binding) return this.binding;
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
		this.#release();
	}

	/** Stop the listener and reject everything still waiting (used on reload and in tests). */
	async close() {
		for (const entry of this.pending.values()) {
			clearTimeout(entry.timer);
			entry.reject(new Error("callback listener closed"));
		}
		this.pending.clear();
		const server = this.server;
		this.server = null;
		this.binding = null;
		if (!server) return;
		server.closeAllConnections?.();
		await new Promise((resolve) => server.close(resolve));
	}

	#release() {
		if (this.pending.size > 0) return;
		const server = this.server;
		this.server = null;
		this.binding = null;
		if (!server) return;
		server.closeAllConnections?.();
		server.close(() => {});
	}

	register(serverName, state) {
		const promise = new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(serverName);
				this.#release();
				reject(new Error("authorization timed out — no browser callback within 10 minutes"));
			}, CALLBACK_TIMEOUT_MS);
			timer.unref?.();
			this.pending.set(serverName, { state, resolve, reject, timer });
		});
		return { promise };
	}

	#handle(request, response) {
		const reply = (status, text) => {
			response.writeHead(status, {
				"content-type": "text/html; charset=utf-8",
				"cache-control": "no-store",
				"referrer-policy": "no-referrer",
				connection: "close"
			});
			response.end(`<!doctype html><meta charset="utf-8"><title>DeepSeek Harness</title><body style="font:15px -apple-system,system-ui;padding:2.5rem;line-height:1.5">${text}</body>`);
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
		const url = new URL(raw, `http://127.0.0.1:${this.port}`);
		const match = /^\/callback\/([^/]+)$/.exec(url.pathname);
		if (!match) {
			reply(404, "Not found.");
			return;
		}
		const serverName = decodeURIComponent(match[1]);
		const entry = this.pending.get(serverName);
		if (!entry) {
			reply(409, `<p><b>${serverName}</b>: no authorization is pending.</p><p>Start the connection again from DeepSeek Harness.</p>`);
			return;
		}
		const error = url.searchParams.get("error");
		const code = url.searchParams.get("code");
		if (!equalState(entry.state, url.searchParams.get("state"))) {
			reply(400, `<p><b>${serverName}</b>: state mismatch, request rejected.</p>`);
			return;
		}
		clearTimeout(entry.timer);
		this.pending.delete(serverName);
		if (error) {
			const description = url.searchParams.get("error_description");
			reply(200, `<p><b>${serverName}</b>: authorization was denied (${error}).</p>`);
			this.#release();
			entry.reject(new Error(`authorization denied: ${error}${description ? ` — ${description}` : ""}`));
			return;
		}
		if (!code) {
			reply(400, `<p><b>${serverName}</b>: callback carried no code.</p>`);
			this.#release();
			entry.reject(new Error("callback carried no authorization code"));
			return;
		}
		reply(200, `<p><b>${serverName}</b>: authorized. You can close this tab.</p>`);
		this.#release();
		entry.resolve({ code, iss: url.searchParams.get("iss") ?? void 0 });
	}
}

export function hubFor(port) {
	const existing = registry.hubs.get(port);
	if (existing) return existing;
	const hub = new CallbackHub(port);
	registry.hubs.set(port, hub);
	return hub;
}

/**
 * Browser windows are a user-visible side effect: at most two automatic opens
 * per server in thirty minutes, so a closed tab or a failed exchange cannot
 * turn a reconnect loop into a storm of windows.
 */
const RETRY_COOLDOWN_MS = 5 * 60 * 1000;

function allowBrowser(serverName) {
	const now = Date.now();
	const blockedUntil = registry.blocked.get(serverName) ?? 0;
	if (now < blockedUntil) {
		log(`blocked:${serverName}`, `${serverName}: last authorization did not complete; not opening another browser window for ${Math.ceil((blockedUntil - now) / 60000)} more minutes — restart DeepSeek Harness to retry now`);
		return false;
	}
	const windowMs = 30 * 60 * 1000;
	const limit = 2;
	const recent = (registry.attempts.get(serverName) ?? []).filter((at) => now - at < windowMs);
	if (recent.length >= limit) {
		log(`limit:${serverName}`, `${serverName}: authorization was already offered ${limit} times in the last 30 minutes; not opening another browser window — restart DeepSeek Harness when you are ready to authorize`);
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
	}

	async load() {
		if (this.store) return this.store;
		const { keychain, file } = await readStores(this.serverName);
		const merged = mergeStores(keychain, file);
		this.store = merged ?? EMPTY_STATE();
		if (merged?.tokens && keychain) {
			let stored = null;
			try {
				stored = JSON.parse(keychain);
			} catch {}
			if (!stored?.tokens) {
				await writeSecret(this.serverName, JSON.stringify(merged)).catch(() => {});
				log(`repair:${this.serverName}`, `${this.serverName}: token from the file store merged into the Keychain entry`);
			}
		}
		return this.store;
	}

	async persist() {
		const snapshot = JSON.stringify(this.store);
		await queueWrite(this.serverName, () => writeSecret(this.serverName, snapshot));
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
		await this.persist();
	}

	async tokens() {
		return (await this.load()).tokens ?? void 0;
	}

	async saveTokens(tokens) {
		await this.load();
		this.store.tokens = tokens;
		await this.persist();
		log(`token:${this.serverName}`, `${this.serverName}: access token stored (${tokens.token_type ?? "bearer"})`);
	}

	async saveCodeVerifier(codeVerifier) {
		await this.load();
		this.store.codeVerifier = codeVerifier;
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
		await this.persist();
	}

	async saveAuthorizationServerUrl(url) {
		await this.load();
		this.store.authorizationServerUrl = url;
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
		await this.persist();
	}

	async state() {
		this.pendingState = randomBytes(24).toString("base64url");
		return this.pendingState;
	}

	/**
	 * The SDK awaits this call, so a busy port surfaces here — before the browser
	 * opens — and a flow already under way is reused, never restarted.
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
		this.hub.releaseIfIdle();
		if (!allowBrowser(this.serverName)) return;
		try {
			await this.hub.ensure();
		} catch (error) {
			log(`port:${this.hub.port}`, `${this.serverName}: ${String(error.message ?? error)}`);
			return;
		}

		const state = this.pendingState ?? randomBytes(24).toString("base64url");
		const { promise } = this.hub.register(this.serverName, state);
		registry.flows.set(this.serverName, promise);
		log(`authorize:${this.serverName}`, `${this.serverName}: authorize at ${url.href}`);
		if (this.oauth.openBrowser !== false) {
			spawn("open", [url.href], { stdio: "ignore", detached: true }).unref();
		}
		promise
			.then(async ({ code, iss }) => {
				const auth = await loadAuth();
				const outcome = await auth(this, {
					serverUrl: this.serverUrl,
					authorizationCode: code,
					...(iss ? { iss } : {})
				});
				log(`result:${this.serverName}`, `${this.serverName}: authorization ${outcome}`);
			})
			.catch((error) => {
				registry.blocked.set(this.serverName, Date.now() + RETRY_COOLDOWN_MS);
				log(`failed:${this.serverName}`, `${this.serverName}: authorization failed: ${String(error.message ?? error)}; no automatic retry for 5 minutes`);
			})
			.finally(() => registry.flows.delete(this.serverName));
	}
}
