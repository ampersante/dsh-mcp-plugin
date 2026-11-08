export function compare(a, b) {
	const parse = (value) => value.split("-")[0].split(".").map((part) => {
		const n = Number(part);
		return Number.isFinite(n) ? n : 0;
	});
	const pa = parse(a);
	const pb = parse(b);
	for (let i = 0; i < 3; i += 1) {
		const d = (pa[i] ?? 0) - (pb[i] ?? 0);
		if (d !== 0) return d;
	}
	// A prerelease sorts below its release.
	const preA = a.includes("-");
	const preB = b.includes("-");
	if (preA !== preB) return preA ? -1 : 1;
	return 0;
}
