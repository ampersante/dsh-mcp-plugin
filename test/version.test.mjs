import test from "node:test";
import assert from "node:assert/strict";
import { compare } from "../tools/version.mjs";

test("0.7.0 sorts below 0.10.0", () => {
	assert.ok(compare("0.7.0", "0.10.0") < 0, "0.7.0 must sort below 0.10.0");
});

test("a prerelease sorts below its release", () => {
	assert.ok(compare("1.0.0-rc.1", "1.0.0") < 0, "1.0.0-rc.1 must sort below 1.0.0");
});

test("equal versions compare equal", () => {
	assert.equal(compare("1.0.0", "1.0.0"), 0);
});

test("0.9.9 sorts below 1.0.0", () => {
	assert.ok(compare("0.9.9", "1.0.0") < 0, "0.9.9 must sort below 1.0.0");
});

test("V1: prerelease identifiers follow SemVer precedence", () => {
	// SemVer 2.0.0 §11: numeric identifiers compare numerically, a shorter set
	// sorts below its longer prefix, and numeric sorts below alphanumeric.
	assert.ok(compare("1.0.0-rc.2", "1.0.0-rc.10") < 0, "rc.2 must sort below rc.10");
	assert.ok(compare("1.0.0-alpha", "1.0.0-alpha.1") < 0, "alpha must sort below alpha.1");
	assert.ok(compare("1.0.0-1", "1.0.0-alpha") < 0, "a numeric identifier must sort below a label");
});
