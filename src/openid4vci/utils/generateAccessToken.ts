import { TokenResponseSchemaType } from '../../types/oid4vci';
import * as crypto from 'node:crypto';
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import * as jose from 'jose';
import { Request, Response } from 'express';
const accessTokenExpirationInSeconds = 8000;


export const keyPairPromise = jose.generateKeyPair('RSA-OAEP-256');

export async function generateAccessToken(ctx: { req: Request, res: Response }): Promise<TokenResponseSchemaType | null> {
	if (ctx.res.headersSent) {
		return null;
	}

	const userSession = ctx.req.authorizationServerState;
	const credentialIssuersIdentifiers: string[] = [];
	
	if (userSession.authorization_details) {
		for (const ad of userSession?.authorization_details) {
			if (ad.locations) {
				credentialIssuersIdentifiers.push(...ad.locations);
			}
		}
	}

	// access_token
	userSession.expires_in = accessTokenExpirationInSeconds;

	// c_nonce
	userSession.c_nonce = crypto.randomBytes(60).toString('base64url');
	userSession.c_nonce_expires_in = accessTokenExpirationInSeconds;



	// store user session in access token
	console.log("User session on AT generation: ", userSession);
	console.log("Serialized user session", AuthorizationServerState.serialize(userSession))
	// const nonSignedJwtStruct = new SignJWT({ userSession: AuthorizationServerState.serialize(userSession) })
	// 	.setAudience(credentialIssuersIdentifiers)
	// 	.setExpirationTime('1h')
	// 	.setSubject('username');
	// const { jws } = await keystoreService.signJwt("authorization_server", nonSignedJwtStruct, "JWT");

	// const { jws } = await keystoreService.signJwt("authorization_server", nonSignedJwtStruct, "JWT");
	// redisModule.storeAccessToken(userSession.access_token, userSession.id)  // store access token

	const jwe = await new jose.EncryptJWT({ userSession: AuthorizationServerState.serialize(userSession) })
		.setAudience(credentialIssuersIdentifiers)
		.setExpirationTime('1h')
		.setSubject('username')
		.setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
		.encrypt((await keyPairPromise).publicKey);

	const tokenResponse: TokenResponseSchemaType = {
		token_type: "Bearer",
		access_token: jwe,
		expires_in: userSession.expires_in,
		c_nonce: userSession.c_nonce,
		c_nonce_expires_in: userSession.c_nonce_expires_in,
	}
	return { ...tokenResponse };
}
