export function generateDataUriFromSvg(
	svgText: string,
	pathsWithValues: { path: string, value: string }[],
): string {

	function escapeSVG(str: string) {
		if (typeof str !== "string") return str;

		return str.replace(/[<>&"']/g, function (match) {
			switch (match) {
				case '<': return '&lt;';
				case '>': return '&gt;';
				case '&': return '&amp;';
				case '"': return '&quot;';
				case "'": return '&apos;';
				default: return match;
			}
		});
	}
	// Regular expression to match the placeholders in the SVG
	const regex = /{{([^}]+)}}/g;

	// Replace placeholders with corresponding values from pathsWithValues
	const replacedSvgText = svgText.replace(regex, (_match, content) => {
		const key = content.trim();

		// Find the matching row by path
		const row = pathsWithValues.find(r => r.path === key);

		// Replace placeholder with row value or replace with an empty string if not found
		return row && row.value ? escapeSVG(String(row.value)) : '';
	});

	// Encode the replaced SVG content into a data URI
	const dataUri = `data:image/svg+xml;utf8,${encodeURIComponent(replacedSvgText)}`;

	return dataUri;
}
