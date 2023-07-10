import { SignVerifiableCredentialJWT } from "@gunet/ssi-sdk";
import { JWK } from "jose";


export interface WalletKeystore {
	getAllPublicKeys(): Promise<{ jwks: JWK[] }>;
	getPublicKeyJwk(credentialIssuerIdentifier: string): Promise<{ jwk: JWK }>;
	signVcJwt(credentialIssuerIdentifier: string, vcjwt: SignVerifiableCredentialJWT<any>): Promise<{ credential: string }>;
}