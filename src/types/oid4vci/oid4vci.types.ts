import { VerifiableCredentialFormat } from 'wallet-common/dist/types';
import { JWK } from 'jose';



export enum GrantType {
	AUTHORIZATION_CODE = "authorization_code",
	PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
	REFRESH_TOKEN = "refresh_token",
}




export type CredentialSupportedBase = {
	id: string,
	format: VerifiableCredentialFormat,
	cryptographic_binding_methods_supported?: string[],
	cryptographic_suites_supported?: string[],
}

// additional attributes for credentials_supported object for the 'jwt_vc_json' format specifically
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-objects-comprising-credenti
// extended by:
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-vc-signed-as-a-jwt-not-usin

export type JwtProof = {
	proof_type?: string;
	jwt?: string;
}


export type ProofHeader = {
	alg: string;

	/**
	 * CONDITIONAL. JWT header containing the key ID.
	 * If the credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the credential shall be bound to.
	 */
	kid?: string;

	/**
	 * CONDITIONAL. JWT header containing the key material the new credential shall be bound to. MUST NOT be present if kid is present.
	 * REQUIRED for EBSI DID Method for Natural Persons.
	 */
	jwk?: JWK;
}

export type ProofPayload = {
	/**
	 * REQUIRED. MUST contain the client_id of the sender.
	 * in DID format
	 */
	iss: string;

	/**
	 * REQUIRED. MUST contain the issuer URL of the credential issuer.
	 */
	aud: string;

	iat: number;


	/**
	 * REQUIRED. MUST be Token Response c_nonce as provided by the issuer.
	 */
	nonce: string;
}



export enum VerifiablePresentationFormat {
	JWT_VP = "jwt_vp"
}

export enum ProofType {
	JWT = "jwt"
}
