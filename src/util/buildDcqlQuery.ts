export function buildDcqlQuery(presentationDefinition: any, body?: any): any {
	const selectedType = body?.type || 'sd-jwt';
	const formatOverride = body?.format;
	const purpose = body?.purpose || presentationDefinition.purpose || 'Purpose not specified';

	// Prepare selected attributes or default to including all
	const selectedPaths = new Set(
		Array.isArray(body?.attributes) ? body.attributes : undefined
	);

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

	/**
	 * Sanitize the descriptor ID to avoid dcql-ts lib error for malformed ids
	**/
	const sanitizeId = (id: string): string =>
		id?.replace(/[^a-zA-Z0-9_-]/g, '_');

	const credentials = [];
	const descriptorIds: string[] = [];

	for (const descriptor of presentationDefinition.input_descriptors || []) {
		const descriptorId = descriptor.id || `${presentationDefinition.id}${credentials.length}`;
		const fields = descriptor?.constraints?.fields ?? [];
		const claims: any[] = [];
		const meta: any = {};
		let format = formatOverride || 'dc+sd-jwt';
		let vctValue: string | undefined;
		let doctypeValue: string | undefined;

		for (const field of fields) {
			const rawPath = field.path[0];

			// Respect selection if provided, otherwise include all
			if (selectedPaths.size > 0 && !selectedPaths.has(rawPath)) continue;

			if (selectedType === 'sd-jwt') {
				if (format === 'vc+sd-jwt' || format === 'dc+sd-jwt') {
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

		const sanitizedId = sanitizeId(descriptorId);
		descriptorIds.push(sanitizedId);

		credentials.push({
			id: sanitizedId,
			format,
			meta,
			...(claims && Object.keys(claims).length > 0 && { claims }) //claims must be non-empty
		});
	}

	const dcqlQuery: any = {
		credentials
	};

	dcqlQuery.credential_sets = [
		{
			options: [descriptorIds],
			purpose
		}
	];
	return dcqlQuery;
}
