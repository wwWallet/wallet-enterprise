import { TokenResponseSchemaType } from '../../types/oid4vci';
import { SignJWT } from 'jose';
import * as crypto from 'node:crypto';
import { keystoreService } from '../../services/instances';
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";

const accessTokenExpirationInSeconds = 8000;

export async function generateAccessToken(userSession: AuthorizationServerState): Promise<TokenResponseSchemaType> {

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
	const nonSignedJwtStruct = new SignJWT({ userSession: AuthorizationServerState.serialize(userSession) })
		.setAudience(credentialIssuersIdentifiers)
		.setExpirationTime('1h')
		.setSubject('username');
	// const { jws } = await keystoreService.signJwt("authorization_server", nonSignedJwtStruct, "JWT");

	const { jws } = await keystoreService.signJwt("authorization_server", nonSignedJwtStruct, "JWT");
	// redisModule.storeAccessToken(userSession.access_token, userSession.id)  // store access token

	

	const tokenResponse: TokenResponseSchemaType = {
		token_type: "Bearer",
		access_token: jws,
		expires_in: userSession.expires_in,
		c_nonce: userSession.c_nonce,
		c_nonce_expires_in: userSession.c_nonce_expires_in,
	}
	return { ...tokenResponse };
}
