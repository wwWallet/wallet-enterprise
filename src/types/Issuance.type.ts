import { z } from 'zod';

export type VcJwtJsonCred = {
	format: "jwt_vc_json",
	types: string[] // VerifiableCredential, UniversityDegreeCredential 
}

export type CredentialOfferCredential = string | VcJwtJsonCred;

export type CredentialOffer = {
	credential_issuer: string,
	credentials: CredentialOfferCredential[],
	grants: {
		"authorization_code": {
			"issuer_state"?: string
		},
		"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
			"pre-authorized_code": string,
      "user_pin_required": boolean
		}
	}
}


export const AuthorizationDetail = z.object({
	type: z.string(),
	format: z.string(),
	types: z.array(z.string())
})