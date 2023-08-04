import { redisModule } from "../../RedisModule";
import { TokenRequestBodySchemaForPreAuthorizedCodeGrantType, TokenResponseSchemaType } from "../../types/oid4vci";
import { generateAccessToken } from "../utils/generateAccessToken";


export async function preAuthorizedCodeGrantTokenEndpoint(body: TokenRequestBodySchemaForPreAuthorizedCodeGrantType): Promise<TokenResponseSchemaType> {
	const userSession = (await redisModule.getSessionByPreAuthorizedCode(body["pre-authorized_code"], body.user_pin)).unwrapOr(null);

	if (!userSession) {
		throw new Error(`No user session was found for authorization code ${body["pre-authorized_code"]}`);
	}
	return generateAccessToken(userSession);
}
