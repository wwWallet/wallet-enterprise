import { Request, Response } from "express";
import z from 'zod';
import crypto from 'node:crypto';
import { authorizationCodeGrantTokenEndpoint } from "../grant_types/AuthorizationCodeGrant";
import { UserSession, redisModule } from "../../RedisModule";
import { GrantType } from "../../types/oid4vci";

const accessTokenExpirationInSeconds = 8000;


const tokenRequestBodySchemaForAuthorizationCodeGrant = z.object({
	grant_type: z.string(),
	code: z.string(),
	code_verifier: z.string(),
	redirect_uri: z.string(),
	client_assertion: z.string().optional(),
	client_assertion_method: z.string().optional()
})

const tokenRequestBodySchemaForPreAuthorizedCodeGrant = z.object({
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


export type TokenRequestBodySchemaForAuthorizationCodeGrantType = z.infer<typeof tokenRequestBodySchemaForAuthorizationCodeGrant>; // string

export type TokenRequestBodySchemaForPreAuthorizedCodeGrantType = z.infer<typeof tokenRequestBodySchemaForPreAuthorizedCodeGrant>; // string
export type TokenResponseSchemaType = z.infer<typeof tokenResponseSchema>;

export async function tokenEndpoint(req: Request, res: Response) {
	console.log("Body ", req.body)

	let body = null;
	let response = null;
	if (!req.body.grant_type) {
		console.log("No grant type was found");
		res.status(500).send({});
		return;
	}

	switch (req.body.grant_type) {
	case GrantType.AUTHORIZATION_CODE:
		body = tokenRequestBodySchemaForAuthorizationCodeGrant.parse(req.body);
		// if (!req.headers.authorization) {
		// 	return res.status(401).send("No authorization header was provided");
		// }
		try {
			response = await authorizationCodeGrantTokenEndpoint(body, req.headers.authorization);
		}
		catch (err) {
			console.error("Error = ", err)
			return res.status(500).json({ error: "Failed"})
		}
		break;
	default:
		console.log("Grant type is not supported");
		return res.status(400).send("Granttype not supported");
		// body = tokenRequestBodySchemaForPreAuthorizedCodeGrant.parse(req.body);
		// response = await preAuthorizedCodeGrantTokenEndpoint(body);
		// break;
	}
	res.setHeader("Cache-Control", "no-store");
	res.json(response);
}


export async function generateToken(userSession: UserSession): Promise<TokenResponseSchemaType> {

	// access_token
	userSession.access_token = crypto.randomBytes(60).toString('base64url');
	userSession.expires_in = accessTokenExpirationInSeconds;

	// c_nonce
	userSession.c_nonce = crypto.randomBytes(60).toString('base64url');
	userSession.c_nonce_expires_in = accessTokenExpirationInSeconds;

	redisModule.storeUserSession(userSession.id, userSession); // update user session object
	redisModule.storeAccessToken(userSession.access_token, userSession.id); // store access token
	
	const tokenResponse: TokenResponseSchemaType = {
		token_type: "Bearer",
		access_token: userSession.access_token,
		expires_in: userSession.expires_in,
		c_nonce: userSession.c_nonce,
		c_nonce_expires_in: userSession.c_nonce_expires_in,
	}
	return { ...tokenResponse };
}
