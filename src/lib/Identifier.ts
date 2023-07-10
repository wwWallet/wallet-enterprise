import { JWK } from "jose";

type SingleKey = {
	id: string;
	kid: string;
	privateKeyJwk: JWK;
	publicKeyJwk: JWK;
	privateKeyEncryptionJwk: JWK;
	publicKeyEncryptionJwk: JWK;
}

export enum SigningAlgorithm {
	EdDSA = "EdDSA",
	ES256 = "ES256",
	RS256 = "RS256",
	ES256K = "ES256K"
}

export type DidEbsiKeyTypeObject = {
	privateKeyHex: string,
  address: string;
  did: string,
	keys: {
		EdDSA?: SingleKey,
		ES256?: SingleKey,
		RS256?: SingleKey,
		ES256K?: SingleKey,
	},
}

export type DidKeyKeyTypeObject = {
	did: string;
	alg: string;
	key: SingleKey;
}


export abstract class Identifier { 
	constructor(public id: string) {}
}

export class KeyMethodIdentifier extends Identifier {
	constructor(public key: DidKeyKeyTypeObject | undefined = undefined, public referenceURI: string | undefined = undefined) {
		super(key?.did as string)
	}
}

export class EbsiLegalPersonMethodIdentifier extends Identifier {
	constructor(public key: DidEbsiKeyTypeObject | undefined = undefined, public referenceURI: string | undefined = undefined) {
		super(key?.did as string)
	}
}

