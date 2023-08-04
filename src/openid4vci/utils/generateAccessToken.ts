import crypto from 'node:crypto';
import { UserSession, redisModule } from "../../RedisModule";
import { TokenResponseSchemaType } from '../../types/oid4vci';

const accessTokenExpirationInSeconds = 8000;

export async function generateAccessToken(userSession: UserSession): Promise<TokenResponseSchemaType> {

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
