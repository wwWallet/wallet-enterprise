

export type CategorizedRawCredentialViewRow = {
	name: string;
	value: string;
}

export type CategorizedRawCredentialView = {
	rows: CategorizedRawCredentialViewRow[]; // REQUIRED
	// add additional data here (footnote, header, ...)
}
