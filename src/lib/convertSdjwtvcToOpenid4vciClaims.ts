type MetadataClaim = {
	path: string[];
	display?: { lang: string; label: string }[];
};

export function convertSdjwtvcToOpenid4vciClaims(
	metadataClaims: MetadataClaim[]
): any[] {

	return metadataClaims.map(claim => {

		const display = (claim.display || []).map(d => ({
			locale: d.lang,
			name: d.label
		}));

		return {
			path: claim.path,
			...(display.length > 0 ? { display } : {})
		};
	});
}
