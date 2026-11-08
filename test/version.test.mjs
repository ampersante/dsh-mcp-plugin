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

test("prerelease labels of one version compare equal", () => {
	// compare() does not order prerelease labels; this test locks that current behaviour.
	assert.equal(compare("1.2.3-alpha", "1.2.3-beta"), 0);
});
