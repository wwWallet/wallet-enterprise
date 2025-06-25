export function buildDcqlQuery(presentationDefinition: any, body: any): any {
	const selectedPaths = new Set(Array.isArray(body.attributes) ? body.attributes : [body.attributes]);
	const fields = presentationDefinition.input_descriptors[0].constraints.fields;
	const selectedType = body.type; // "sd-jwt" or "mdoc"

	const descriptorId = body.descriptorId;
	let format = body.format;
	const claims: any[] = [];

	let vctValue: string | undefined;
	let doctypeValue: string | undefined;
	const meta: any = {};

	/* 
	 * parser to convert SD-JWT fields like $.age_equal_or_over['14']
	 *  into['age_equal_or_over', '14'] 
	 */
	const parseSdJwtPath = (p: string): string[] => {
		if (!p.startsWith('$')) return [p];
		let remainder = p.replace(/^\$\./, '');
		remainder = remainder.replace(/\[['"]([^'"\]]+)['"]\]/g, '.$1');
		return remainder.split('.').filter(Boolean);
	};

	for (const field of fields) {
		if (!selectedPaths.has(field.path[0])) continue;

		const rawPath = field.path[0];

		if (selectedType === 'sd-jwt') {
			if (format === "vc+sd-jwt" || format === 'dc+sd-jwt') {
				const pathSegments = parseSdJwtPath(rawPath);
				const topKey = pathSegments[0];
				if (topKey === 'vct' && field.filter?.const) {
					vctValue = field.filter.const;
					meta.vct_values = [vctValue];
				} else {
					claims.push({ path: pathSegments });
				}
			}
		} else if (selectedType === 'mdoc') {
			// Match: $['namespace']['field.subfield']
			const match = rawPath.match(/^\$\['([^']+)'\]\['([^']+)'\]$/);
			if (!match) continue;

			const [_, namespace, subpath] = match;
			const subPathSegments = subpath.split('.');

			claims.push({
				path: [namespace, ...subPathSegments],
				intent_to_retain: false
			});

			format = 'mso_mdoc';
			doctypeValue = namespace;
			if (doctypeValue) {
				meta.doctype_value = doctypeValue;
			}
		}
	}

	/**
	 * Sanitizes the descriptor ID to avoid dcql-ts lib error for malformed ids
	 **/
	function sanitizeId(id: string): string {
		return id.replace(/[^a-zA-Z0-9_-]/g, '_');
	}
	const sanitizedId = sanitizeId(descriptorId);

	const dcqlQuery = {
		credentials: [
			{
				id: sanitizedId,
				format,
				meta,
				claims
			}
		],
		credential_sets: [
			{
				options: [[sanitizedId]],
				purpose: body.purpose || ""
			}
		]
	};

	return dcqlQuery;
}
