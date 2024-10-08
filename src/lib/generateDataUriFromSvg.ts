type CategorizedRawCredentialViewRow = {
	name: string;
	value: string | number;
};

export function generateDataUriFromSvg(
	svgText: string,
	rows: CategorizedRawCredentialViewRow[]
): string {
	// Regular expression to match the placeholders in the SVG
	const regex = /{{\/([^}]+)}}/g;

	// Replace placeholders with corresponding values from rows
	const replacedSvgText = svgText.replace(regex, (_match, content) => {
		const key = content.trim();
		const cleanedKey = key.startsWith('/') ? key.slice(1) : key;

		// Find the matching row by name
		const row = rows.find(r => r.name === cleanedKey);

		// Replace placeholder with row value or replace with 'null' if not found
		return row && row.value ? String(row.value) : '';
	});

	// Encode the replaced SVG content into a data URI
	const dataUri = `data:image/svg+xml;utf8,${encodeURIComponent(replacedSvgText)}`;

	return dataUri;
}
