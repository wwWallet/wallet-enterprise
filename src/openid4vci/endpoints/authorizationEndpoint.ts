import { Request, Response } from "express";
import z from 'zod';
import { randomUUID } from "crypto";
import { UserSession, redisModule } from "../../RedisModule";
import crypto from 'node:crypto';

const authorizationRequestQueryParamsSchema = z.object({
	response_type: z.string(),
	client_id: z.string(),
	code_challenge: z.string(),
	code_challenge_method: z.string(),
	authorization_details: z.string(),
	redirect_uri: z.string()
})

const authorizationDetailsSchema = z.array(z.object({
	type: z.string(),
	format: z.string(),
	types: z.array(z.string()),
	locations: z.array(z.string()).optional()
}))

export type AuthorizationRequestQueryParamsSchemaType = z.infer<typeof authorizationRequestQueryParamsSchema>;
export type AuthorizationDetailsSchemaType = z.infer<typeof authorizationDetailsSchema>;

export async function authorizationEndpoint(req: Request, res: Response) {
	const params = authorizationRequestQueryParamsSchema.parse(req.query);

	console.log("Authorization details = ", params.authorization_details)
	const authorizationDetails = authorizationDetailsSchema.parse(JSON.parse(params.authorization_details));

	// TODO: make sure that authorization details are correct and conform to the ones publish on the CredentialIssuerMetadata
	// TODO: make sure that the client_id exists in the clients table

	const sessionid = randomUUID();
	const newUserSession: UserSession = {
		id: sessionid,
		authorizationReqParams: params,
		authorizationDetails: authorizationDetails
	}

	redisModule.storeUserSession(sessionid, newUserSession);
	res.cookie('sessid', sessionid);
	res.redirect('/authorization/login');
}

/**
 * @throws
 * @param userSession 
 * @returns 
 */
export async function generateAuthorizationResponse(userSession: UserSession, selectedCredentialIdList: string[]): Promise<{authorizationResponseURL: string}> {
	const client_id = userSession.authorizationReqParams?.client_id;
	if (!client_id) {
		throw "\nNo client id was defined on the authorization request";
	}

	console.log("User session = ", userSession.authorizationReqParams);

	// Registered client checks
	// const clientFetchRes = await getOpenid4vciClientByClientId(client_id);
	// if (clientFetchRes.err) {
	// 	throw `\nClient with client_id "${client_id}" does not exist`;
	// }

	// const client = clientFetchRes.unwrap();
	// console.log("client = ", client)
	// if (!userSession.authorizationReqParams?.redirect_uri || 
	// 	userSession.authorizationReqParams.redirect_uri !== client.redirect_uri) {
			
	// 		throw `\nParameter "redirect_uri" was not provided on the Authorization Request or `+ 
	// 			`AuthorizationRequest.redirect_uri is not the same with the redirect_uri of the registered client ${client.client_id} on the database`;
	// }

	if (!userSession?.authorizationReqParams?.redirect_uri) {
		throw "Redirect uri not found in params"
	}
	console.log("Redirect uri = ", userSession.authorizationReqParams)


	userSession.authorization_code = crypto.randomBytes(60).toString('base64url');
	const authorizationResponseURL = new URL(userSession?.authorizationReqParams?.redirect_uri);
	authorizationResponseURL.searchParams.append("code", userSession.authorization_code);
	userSession.selectedCredentialIdList = [...selectedCredentialIdList];
	
	redisModule.storeUserSession(userSession.id, userSession).catch(err => {
		console.log("Failed to store user session")
		console.log(err);
	});

	redisModule.storeAuthorizationCode(userSession.authorization_code, userSession.id).catch(err => {
		console.log("Failed to store authorization code in redis")
		console.log(err);
	});

	return { authorizationResponseURL: authorizationResponseURL.toString() };
}