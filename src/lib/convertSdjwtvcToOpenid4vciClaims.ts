type MetadataClaim = {
	path: string[];
	display?: { lang: string; label: string }[];
};

type JsonSchema = {
	required?: string[];
};

export function convertSdjwtvcToOpenid4vciClaims(
	metadataClaims: MetadataClaim[],
	schema: JsonSchema
): any[] {
	const requiredTopLevel = new Set(schema.required || []);

	return metadataClaims.map(claim => {
		const topKey = claim.path[0];
		const isMandatory = requiredTopLevel.has(topKey);

		const display = (claim.display || []).map(d => ({
			locale: d.lang,
			name: d.label
		}));

		return {
			path: claim.path,
			...(isMandatory ? { mandatory: true } : {mandatory: false}),
			...(display.length > 0 ? { display } : {})
		};
	});
}
