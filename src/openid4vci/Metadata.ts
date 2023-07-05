import { UserSession } from "../RedisModule";
import { VerifiableCredentialFormat } from "../types/oid4vci";


export type SignerFn = (userSession: UserSession, holderDID: string) => Promise<{ format: VerifiableCredentialFormat, credential: any }>;


export type CategorizedRawCredentialViewRow = {
	name: string;
	value: string;
}

export type CategorizedRawCredentialView = {
	rows: CategorizedRawCredentialViewRow[]; // REQUIRED
	// add additional data here (footnote, header, ...)
}

export type CategorizedRawCredential<T> = {
	credential_id: string;
	supportedCredentialIdentifier: string;
	credentialIssuerIdentifier: string; // a uri
	rawData: T; 
	view: CategorizedRawCredentialView
}

export type ResourceCallbackFn = (userSession: UserSession) => Promise<CategorizedRawCredential<any>[]>; // returns an array of rawData
