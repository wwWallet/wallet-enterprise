import { z } from 'zod'
import { ProofType, VerifiableCredentialFormat } from './oid4vci.types';

export const authorizationRequestQueryParamsSchema = z.object({
	// required
	response_type: z.string(),
	client_id: z.string(),
	redirect_uri: z.string(),
	scope: z.string(),

	// optional
	issuer_state: z.string().optional(),
	state: z.string().optional(),
	authorization_details: z.string().optional(),
	code_challenge: z.string().optional(),
	code_challenge_method: z.string().optional(),
	client_metadata: z.string().optional(),
	nonce: z.string().optional(),
});


export const authorizationDetailsSchema = z.array(z.object({
	type: z.string(),
	format: z.string(),
	types: z.array(z.string()),
	locations: z.array(z.string()).optional()
}))



export const tokenRequestBodySchema = z.object({
	grant_type: z.string(),
	code: z.string().optional(),
	code_verifier: z.string().optional(),
	redirect_uri: z.string().optional(),
	"pre-authorized_code": z.string().optional(),
	user_pin: z.string().optional()
});


export const tokenRequestBodySchemaForAuthorizationCodeGrant = z.object({
	grant_type: z.string(),
	code: z.string(),
	code_verifier: z.string(),
	redirect_uri: z.string().optional(),
	client_assertion: z.string().optional(),
	client_assertion_method: z.string().optional()
})

export const tokenRequestBodySchemaForPreAuthorizedCodeGrant = z.object({
	grant_type: z.string(),
	"pre-authorized_code": z.string(),
	user_pin: z.string(),
})


export const tokenResponseSchema = z.object({
	token_type: z.string(),
	access_token: z.string(),
	expires_in: z.number(),
	c_nonce: z.string(),
	c_nonce_expires_in: z.number()
});


export const credentialResponseSchema = z.object({
	format: z.string(),
	credential: z.string().optional(),
	acceptance_token: z.string().optional(),
	c_nonce: z.string().optional(),
	c_nonce_expires_in: z.number().optional()
});


export const credentialRequestBodySchema = z.object({
	format: z.nativeEnum(VerifiableCredentialFormat),
	types: z.array(z.string()),
	proof: z.object({
		proof_type: z.nativeEnum(ProofType),
		jwt: z.string()
	})
})




export type AuthorizationRequestQueryParamsSchemaType = z.infer<typeof authorizationRequestQueryParamsSchema>;
export type AuthorizationDetailsSchemaType = z.infer<typeof authorizationDetailsSchema>;

export type TokenRequestBodySchemaType = z.infer<typeof tokenRequestBodySchema>;
export type CredentialRequestBodySchemaType = z.infer<typeof credentialRequestBodySchema>;

export type TokenResponseSchemaType = z.infer<typeof tokenResponseSchema>;
export type CredentialResponseSchemaType = z.infer<typeof credentialResponseSchema>;
export type TokenRequestBodySchemaForAuthorizationCodeGrantType = z.infer<typeof tokenRequestBodySchemaForAuthorizationCodeGrant>; // string

export type TokenRequestBodySchemaForPreAuthorizedCodeGrantType = z.infer<typeof tokenRequestBodySchemaForPreAuthorizedCodeGrant>; // string

export type CredentialRequestBody = z.infer<typeof credentialRequestBodySchema>;
