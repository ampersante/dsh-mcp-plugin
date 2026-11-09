#!/usr/bin/env node
/**
 * Update `dsh-mcp-oauth` without npm or pnpm.
 *
 * The package is versioned by git tags. An update:
 *   1. exports the requested ref into a staging directory,
 *   2. runs the package's own test suite with the bundled Node,
 *   3. backs up the installed copy,
 *   4. swaps it in and touches the profile patch to trigger a reload,
 *   5. restores the backup if anything fails.
 *
 * Usage:
 *   node tools/update.mjs --repo <path> [--ref <tag>] [--target <dir>] [--patch <file>] [--check]
 *
 * Defaults: --ref is the highest semver tag, --target is the installed plugin in
 * the desktop profile, --patch is that profile's cordis.patch.yml.
 */
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { compare } from "./version.mjs";

const DESKTOP = join(process.env.HOME ?? "", ".dsh", "profiles", "desktop");

function arg(flag, fallback) {
	const index = process.argv.indexOf(flag);
	return index === -1 ? fallback : process.argv[index + 1];
}

const repo = resolve(arg("--repo", "."));
const target = resolve(arg("--target", join(DESKTOP, "node_modules", "dsh-mcp-oauth")));
const patch = resolve(arg("--patch", join(DESKTOP, "cordis.patch.yml")));
const node = arg("--node", process.execPath);
const checkOnly = process.argv.includes("--check");

function git(...args) {
	return execFileSync("git", ["-C", repo, ...args], { encoding: "utf8" }).trim();
}

function refresh() {
	const remotes = git("remote");
	if (!remotes) return;
	try {
		execFileSync("git", ["-C", repo, "fetch", "--tags", "--prune", "--quiet"], { stdio: "pipe" });
	} catch (error) {
		console.error(`warning: could not fetch from the remote (${String(error.message ?? error).split("\n")[0]}); using local tags`);
	}
}

function tags() {
	refresh();
	return git("tag", "--list", "v*")
		.split("\n")
		.filter(Boolean)
		.sort((a, b) => compare(a.replace(/^v/, ""), b.replace(/^v/, "")));
}

function installedVersion() {
	try {
		return JSON.parse(readFileSync(join(target, "package.json"), "utf8")).version;
	} catch {
		return null;
	}
}

const available = tags();
if (available.length === 0) {
	console.error(`no v* tags in ${repo}`);
	process.exit(2);
}
const ref = arg("--ref", available.at(-1));
if (ref === undefined || ref === "") {
	console.error("--ref needs a value: pass an existing v* tag, for example --ref v0.6.0");
	process.exit(2);
}
if (ref.startsWith("-")) {
	console.error(`--ref needs a tag name, not an option: ${ref}`);
	process.exit(2);
}
try {
	// Exact tag name only: `rev-parse --verify` would also accept expressions
	// such as `v0.8.2^{tree}` or `v0.8.2~0`, which export another object.
	git("show-ref", "--verify", "--quiet", `refs/tags/${ref}`);
} catch {
	console.error(`ref must be an existing v* tag: ${ref}`);
	process.exit(2);
}
const version = ref.replace(/^v/, "");
const current = installedVersion();

if (checkOnly) {
	console.log(JSON.stringify({ installed: current, available: version, update: current !== version }, null, 2));
	process.exit(0);
}

const staging = mkdtempSync(join(tmpdir(), "dsh-mcp-oauth-"));
const backup = `${target}.backup-${Date.now()}`;
let swapped = false;

try {
	const paths = ["index.js", "oauth.js", "package.json", "test", "tools/version.mjs"];
	// Tags from before the terminal authorizer do not carry this file, and
	// `git archive` fails the whole export on a missing path.
	for (const optional of ["tools/authorize.mjs", "tools/update.mjs"]) {
		try {
			git("cat-file", "-e", `${ref}:${optional}`);
			paths.push(optional);
		} catch {}
	}
	const archive = execFileSync("git", ["-C", repo, "archive", "--format=tar", ref, ...paths], { maxBuffer: 64 * 1024 * 1024 });
	execFileSync("tar", ["-x", "-C", staging], { input: archive });
	const staged = staging;
	if (!existsSync(join(staged, "package.json"))) throw new Error(`ref ${ref} does not contain package.json`);

	console.log(`testing ${ref} with ${node}`);
	execFileSync(node, ["--test", "--test-concurrency=1", "test/**/*.test.mjs"], { cwd: staged, stdio: "inherit", timeout: 180000 });

	if (existsSync(target)) renameSync(target, backup);
	swapped = true;
	mkdirSync(join(target, ".."), { recursive: true });
	cpSync(staged, target, { recursive: true });

	if (existsSync(patch)) {
		writeFileSync(patch, readFileSync(patch));
		console.log(`installed ${installedVersion() ?? version}${current ? ` (was ${current})` : ""} -> ${target}`);
		console.log("profile reload touched:", patch);
	} else {
		console.log(`installed ${installedVersion() ?? version}${current ? ` (was ${current})` : ""} -> ${target}`);
		console.log("profile patch not found, reload not triggered:", patch);
	}
} catch (error) {
	if (swapped) {
		rmSync(target, { recursive: true, force: true });
		if (existsSync(backup)) renameSync(backup, target);
		console.error(`update failed, restored ${current ?? "previous"}: ${String(error.message ?? error)}`);
	} else {
		console.error(`update failed before install: ${String(error.message ?? error)}`);
	}
	if (existsSync(backup)) console.error(`previous copy kept at ${backup}`);
	process.exitCode = 1;
} finally {
	rmSync(staging, { recursive: true, force: true });
	if (existsSync(backup) && process.exitCode !== 1) rmSync(backup, { recursive: true, force: true });
}
