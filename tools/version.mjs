export function compare(a, b) {
	const parse = (value) => {
		// Build metadata names a build of the same version, so it never orders.
		const text = String(value).split("+")[0];
		const dash = text.indexOf("-");
		const core = dash === -1 ? text : text.slice(0, dash);
		// Core identifiers stay decimal strings: Number conflates neighbouring
		// integers past 2^53, and compareNumeric orders them exactly.
		const identifiers = core.split(".");
		return { identifiers, prerelease: dash === -1 ? [] : text.slice(dash + 1).split(".") };
	};
	const pa = parse(a);
	const pb = parse(b);
	for (let i = 0; i < 3; i += 1) {
		const d = compareNumeric(pa.identifiers[i] ?? "0", pb.identifiers[i] ?? "0");
		if (d !== 0) return d;
	}
	// A prerelease sorts below its release.
	if (pa.prerelease.length === 0 || pb.prerelease.length === 0) {
		if (pa.prerelease.length === pb.prerelease.length) return 0;
		return pa.prerelease.length === 0 ? 1 : -1;
	}
	// SemVer 2.0.0 §11: numeric identifiers compare numerically and below
	// alphanumeric ones, and a shorter set sorts below its longer prefix.
	const shared = Math.min(pa.prerelease.length, pb.prerelease.length);
	for (let i = 0; i < shared; i += 1) {
		const left = pa.prerelease[i];
		const right = pb.prerelease[i];
		const leftNumeric = /^\d+$/.test(left);
		const rightNumeric = /^\d+$/.test(right);
		let d;
		if (leftNumeric && rightNumeric) d = compareNumeric(left, right);
		else if (leftNumeric !== rightNumeric) d = leftNumeric ? -1 : 1;
		else d = left < right ? -1 : left > right ? 1 : 0;
		if (d !== 0) return d;
	}
	return pa.prerelease.length - pb.prerelease.length;
}

/**
 * Compare decimal identifiers as strings: Number loses precision past 2^53,
 * so two neighbouring identifiers would look equal.
 */
function compareNumeric(left, right) {
	const a = left.replace(/^0+/, "");
	const b = right.replace(/^0+/, "");
	if (a.length !== b.length) return a.length - b.length;
	return a < b ? -1 : a > b ? 1 : 0;
}
