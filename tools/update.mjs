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

function tags() {
	return git("tag", "--list", "v*")
		.split("\n")
		.filter(Boolean)
		.sort((a, b) => compare(a.replace(/^v/, ""), b.replace(/^v/, "")));
}

function compare(a, b) {
	const pa = a.split(".").map(Number);
	const pb = b.split(".").map(Number);
	for (let i = 0; i < 3; i += 1) {
		const d = (pa[i] ?? 0) - (pb[i] ?? 0);
		if (d !== 0) return d;
	}
	return 0;
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
	const archive = execFileSync("git", ["-C", repo, "archive", "--format=tar", ref, "pkg"], { maxBuffer: 64 * 1024 * 1024 });
	execFileSync("tar", ["-x", "-C", staging], { input: archive });
	const staged = join(staging, "pkg");
	if (!existsSync(join(staged, "package.json"))) throw new Error(`ref ${ref} does not contain pkg/`);

	console.log(`testing ${ref} with ${node}`);
	execFileSync(node, ["--test"], { cwd: staged, stdio: "inherit" });

	if (existsSync(target)) renameSync(target, backup);
	mkdirSync(join(target, ".."), { recursive: true });
	cpSync(staged, target, { recursive: true });
	swapped = true;

	if (existsSync(patch)) {
		writeFileSync(patch, readFileSync(patch));
		console.log(`installed ${version}${current ? ` (was ${current})` : ""} -> ${target}`);
		console.log("profile reload touched:", patch);
	} else {
		console.log(`installed ${version}${current ? ` (was ${current})` : ""} -> ${target}`);
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
	process.exitCode = 1;
} finally {
	rmSync(staging, { recursive: true, force: true });
	if (existsSync(backup) && process.exitCode !== 1) rmSync(backup, { recursive: true, force: true });
}
