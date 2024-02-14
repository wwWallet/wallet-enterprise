import { JWK } from "jose";
import { z } from "zod";

type SingleKey = {
	id: string;
	kid: string;
	privateKeyJwk?: JWK;
	publicKeyJwk?: JWK;
	privateKeyEncryptionJwk?: JWK;
	publicKeyEncryptionJwk?: JWK;
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


export const KeyDescriptorSchema = z.object({
	privateKeyJwk: z.any(),
	publicKeyJwk: z.any()
});


export const EbsiLegalPersonMethodIdentifierKeySchema = z.object({
	did: z.string(),
	didVersion: z.literal(1),
	keys: z.object({
		ES256: KeyDescriptorSchema.optional(),
		ES256K: KeyDescriptorSchema.optional(),
		EdDSA: KeyDescriptorSchema.optional(),
	})
});


export const KeyIdentifierKeySchema = z.object({
	keys: z.object({
		ES256: KeyDescriptorSchema.optional(),
		ES256K: KeyDescriptorSchema.optional(),
		EdDSA: KeyDescriptorSchema.optional(),
	})
});