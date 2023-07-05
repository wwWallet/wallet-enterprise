import { JWK } from "jose";

type LegalPersonKey = {
	id: string;
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

export type LegalPersonWallet = {
	privateKeyHex: string,
  address: string;
  did: string,
	keys: {
		EdDSA?: LegalPersonKey,
		ES256?: LegalPersonKey,
		RS256?: LegalPersonKey,
		ES256K?: LegalPersonKey,
	},
}
