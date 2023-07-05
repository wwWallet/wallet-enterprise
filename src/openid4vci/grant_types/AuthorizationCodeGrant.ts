import { redisModule } from "../../RedisModule";
import { TokenRequestBodySchemaForAuthorizationCodeGrantType, generateToken } from "../endpoints/tokenEndpoint";

export async function authorizationCodeGrantTokenEndpoint(body: TokenRequestBodySchemaForAuthorizationCodeGrantType, _authorizationHeader?: string) {
	// TODO: validate the code verifier...

	// let client: ClientEntity;
	// if (authorizationHeader) {
	// 	// TODO: Verify client_id and client_secret (only registered clients are accepted)
	// 	const clientAuthenticationType = authorizationHeader.split(' ')[0];
	// 	if (clientAuthenticationType != "Basic") {
	// 		throw "Client authentication type is not supported"
	// 	}
	// 	const [_, b64Credential] = authorizationHeader.split(' ');
	// 	if (!b64Credential) {
	// 		throw "Basic credentials not found";
	// 	}
	// 	const decodedCredential = Buffer.from(b64Credential, 'base64').toString('utf-8');
	// 	const [client_id, client_secret] = decodedCredential.split(':');
	// 	if (!client_id || !client_secret) {
	// 		throw "Client id or client secret is not defined in Basic credentials";
	// 	}
	// 	const clientFetchRes = await getOpenid4vciClientByClientIdAndSecret(client_id, client_secret);
	// 	if (clientFetchRes.err)
	// 		throw "Client not found by client_id and client_secret";
	// 	client = clientFetchRes.unwrap();
	// 		// TODO: verify redirect_uri based on client id
	// 	if (client.redirect_uri !== body.redirect_uri)
	// 		throw "Redirect uri is not the same with the registered client";
	// }
	// else if (body.client_assertion && body.client_assertion_method) {
	// 	// set the client entity
	// 	const [_header, _payload, _] = body.client_assertion.split('.')
	// 		.map((part, index) => index != 2 ? JSON.parse(base64url.decode(part)) : part);
		
		
		
	// 	// const { kid } = header as { kid?: string };
	// 	// const { iss, aud } = payload as { iss?: string, aud?: string };
	// 	// use kid to find the user in the Client DB in the jwks
	// 	// verify that aud matches the our issuer.
	// }
	// else {
	// 	throw "There is no way to authenticate the client"
	// }




	
	const userSession = await redisModule.getSessionByAuthorizationCode(body.code);
	if (!userSession) {
		throw `No user session was found for authorization code ${body.code}`
	}
	return generateToken(userSession);
}