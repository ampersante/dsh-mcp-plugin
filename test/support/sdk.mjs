/**
 * The MCP SDK used by the exchange test.
 *
 * The plugin imports `@modelcontextprotocol/client` by bare name, so the test
 * needs a real copy of that package. It is taken from a directory the owner
 * provides, never from the application bundle: the tests read only their own
 * temporary files and this one directory, and skip when it is absent.
 *
 * Point `DSH_MCP_OAUTH_SDK` (or place the package at `~/.dsh/mcp-oauth-sdk`)
 * at a directory holding either the package itself or a `node_modules` tree.
 */
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export const SDK_PACKAGE = "@modelcontextprotocol/client";
export const SDK_ENTRY = "dist/index.mjs";

/** Where a copy of the SDK may live; overridable for a different checkout. */
export const SDK_ROOT = process.env.DSH_MCP_OAUTH_SDK ?? join(homedir(), ".dsh", "mcp-oauth-sdk");

const CANDIDATES = [
	join(SDK_ROOT, "node_modules", ...SDK_PACKAGE.split("/"), ...SDK_ENTRY.split("/")),
	join(SDK_ROOT, ...SDK_ENTRY.split("/"))
];

/**
 * Returns the file URL of the SDK entry point, or `null` when no copy is
 * installed. A copy that exists but is incomplete throws, so a broken
 * installation never reads as "no SDK here".
 */
export async function resolveSdk() {
	const entry = CANDIDATES.find((candidate) => existsSync(candidate));
	if (entry === void 0) {
		if (!existsSync(SDK_ROOT)) return null;
		throw new Error(
			`${SDK_PACKAGE}: ${SDK_ROOT} exists but holds no ${SDK_ENTRY}; expected either ${CANDIDATES[0]} or ${CANDIDATES[1]}`
		);
	}
	const url = pathToFileURL(entry).href;
	await import(url);
	return { url };
}

/**
 * Makes `import "@modelcontextprotocol/client"` resolve to that copy.
 *
 * Must run before `oauth.js` is imported; `registerHooks` is loaded lazily so
 * this module itself still loads on an older Node.
 */
export async function installResolveHook(url) {
	const { registerHooks } = await import("node:module");
	if (typeof registerHooks !== "function") {
		throw new Error(`node:module has no registerHooks in Node ${process.version}; Node 22.15+ or 24 is required to load the MCP SDK`);
	}
	registerHooks({
		resolve(specifier, context, nextResolve) {
			if (specifier === SDK_PACKAGE) return { url, shortCircuit: true };
			return nextResolve(specifier, context);
		}
	});
}
