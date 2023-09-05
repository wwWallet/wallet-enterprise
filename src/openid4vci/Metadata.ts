


export enum IssuanceFlow {
	DEFERRED,
	IN_TIME
}

export type CategorizedRawCredentialViewRow = {
	name: string;
	value: string;
}

export type CategorizedRawCredentialView = {
	rows: CategorizedRawCredentialViewRow[]; // REQUIRED
	// add additional data here (footnote, header, ...)
}