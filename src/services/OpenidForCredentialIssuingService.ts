import { Request, Response } from "express";
import { CredentialPool, OpenidForCredentialIssuingInterface, OpenidForPresentationsReceivingInterface } from "./interfaces";
import { AuthorizationDetailsSchemaType, AuthorizationRequestQueryParamsSchemaType, CredentialRequestBody, GrantType, authorizationDetailsSchema, authorizationRequestQueryParamsSchema, credentialRequestBodySchema, tokenRequestBodySchemaForAuthorizationCodeGrant, tokenRequestBodySchemaForPreAuthorizedCodeGrant } from "../types/oid4vci";
import { randomUUID } from "node:crypto";
import { UserSession, redisModule } from "../RedisModule";
import { DID_AUTHENTICATION_MECHANISM_USED, DIDAuthenticationMechanism } from "../configuration/authentication/auth.config";
import { inject, injectable } from "inversify";
import { TYPES } from "./types";
import { AUTHORIZATION_ENTRYPOINT } from "../authorization/constants";
import crypto from 'node:crypto';
import { authorizationCodeGrantTokenEndpoint } from "../openid4vci/grant_types/AuthorizationCodeGrant";
import _ from "lodash";
import { issuersConfigurations } from "../configuration/IssuersConfiguration";
import { verifyProof } from "../openid4vci/Proof/verifyProof";
import 'reflect-metadata';
import { loadCategorizedRawCredentialsToUserSession } from "../authorization/consentPage";
import { IssuanceFlow } from "../openid4vci/Metadata";
import { preAuthorizedCodeGrantTokenEndpoint } from "../openid4vci/grant_types/PreAuthorizedCodeGrant";

type IssuanceState = {
	authorizationRequest: AuthorizationRequestQueryParamsSchemaType
}



const issuanceStates = new Map<string, IssuanceState>();

@injectable()
export class OpenidForCredentialIssuingService implements OpenidForCredentialIssuingInterface {

	
	constructor(
		@inject(TYPES.OpenidForPresentationsReceivingService) private openidForPresentationReceivingService: OpenidForPresentationsReceivingInterface,
		@inject(TYPES.CredentialPoolService) private credentialPoolService: CredentialPool,
	) { }

	metadataRequestHandler(_req: Request, _res: Response): Promise<void> {
		throw new Error("Method not implemented.");
	}

	async authorizationRequestHandler(req: Request, res: Response): Promise<void> {
		const params = authorizationRequestQueryParamsSchema.parse(req.query);
		console.log("Params = ", params)
		if (!params.authorization_details) {
			res.status(400).send({ error: "Authorization Details is missing" })
			return
		}
	
		console.log("Authorization details = ", params.authorization_details)
		const { success } = authorizationDetailsSchema.safeParse(JSON.parse(params.authorization_details))
		if (!success) {
			res.status(400).send({ error: "Inavlid authorization details" });
			return;
		}
		const authorizationDetails = JSON.parse(params.authorization_details) as AuthorizationDetailsSchemaType;
	
		// TODO: make sure that authorization details are correct and conform to the ones publish on the CredentialIssuerMetadata
		// TODO: make sure that the client_id exists in the clients table
	
		const sessionid = randomUUID();
		issuanceStates.set(sessionid, { authorizationRequest: params });


		const newUserSession: UserSession = {
			id: sessionid,
			authorizationReqParams: params,
			authorizationDetails: authorizationDetails
		}
	
		await redisModule.storeUserSession(sessionid, newUserSession);
		res.cookie('sessid', sessionid);
	
		let redirected = false;
		(res.redirect as any) = (url: string): void => {
			redirected = true;
			// Perform the actual redirect
			res.location(url);
			res.statusCode = 302;
			res.end();
		};
	

		if (DID_AUTHENTICATION_MECHANISM_USED == DIDAuthenticationMechanism.OPENID4VP_ID_TOKEN ||
				DID_AUTHENTICATION_MECHANISM_USED == DIDAuthenticationMechanism.OPENID4VP_VP_TOKEN) {
	
			await this.openidForPresentationReceivingService.authorizationRequestHandler(req, res, sessionid);
			if (redirected) {
				return;
			}
			return;
		}
		else {
			console.log("Redirecting...")
			res.redirect(AUTHORIZATION_ENTRYPOINT);
			return;
		}
	}

	async sendAuthorizationResponse(req: Request, res: Response, bindedUserSessionId: string, selectedCredentialIdList?: string[]): Promise<void> {
		const userSessionID = bindedUserSessionId;
		try {
			await loadCategorizedRawCredentialsToUserSession(req, userSessionID);
		}
		catch(e) { }
		
		if (!userSessionID) {
			res.status(400).send({ error: "No session was found"})
			return;
		}
		const issuanceState = issuanceStates.get(userSessionID);
		if (!issuanceState) {
			const msg = { error: "Unable to send authorization response", error_description: "No issuanceState was found for this user session id"};
			console.error(msg);
			throw new Error(JSON.stringify(msg));
		}

		const client_id = issuanceState.authorizationRequest?.client_id;
		if (!client_id) {
			throw new Error("Error on sendAuthorizationResponse(): No client id was defined on the authorization request");
		}
	
		if (!issuanceState?.authorizationRequest?.redirect_uri) {
			throw new Error("Redirect uri not found in params");
		}
	
	
		const userSession = await redisModule.getUserSession(userSessionID);
		if (!userSession) {
			const msg = { 
				error: "Empty user session",
				error_description: "No session was found for a specific userSessionID"
			};
			console.error(msg);
			throw new Error(JSON.stringify(msg));
		}
		
		const authorization_code = crypto.randomBytes(60).toString('base64url');
		userSession.authorization_code = authorization_code;

		const authorizationResponseURL = new URL(issuanceState?.authorizationRequest?.redirect_uri);
		authorizationResponseURL.searchParams.append("code", authorization_code);
		
		if (issuanceState.authorizationRequest.state) {
			authorizationResponseURL.searchParams.append("state", issuanceState.authorizationRequest.state);
		}

		if (selectedCredentialIdList) {
			userSession.selectedCredentialIdList = [...selectedCredentialIdList];
		}

		
		await redisModule.storeUserSession(userSession.id, userSession).catch(err => {
			console.log("Failed to store user session")
			console.log(err);
		});
	
		await redisModule.storeAuthorizationCode(userSession.authorization_code, userSession.id).catch(err => {
			console.log("Failed to store authorization code in redis")
			console.log(err);
		});

		console.log("Redirecting to ...", authorizationResponseURL.toString())
		res.redirect(authorizationResponseURL.toString());
	}


	async tokenRequestHandler(req: Request, res: Response): Promise<void> {
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
				let userSession = await redisModule.getSessionByAuthorizationCode(body.code);
				if (!userSession)
					throw new Error("Could not get session");
				if (!userSession.categorizedRawCredentials) {
					await loadCategorizedRawCredentialsToUserSession(req, userSession.id);
					userSession = await redisModule.getUserSession(userSession.id);
					if (!userSession)
						throw new Error("Could not get session");
				}
				if (!userSession.categorizedRawCredentials)
					throw new Error("Could not get categorized raw credential");

				response = await authorizationCodeGrantTokenEndpoint(body, req.headers.authorization);
				const { access_token } = response;
				
				await Promise.all(userSession.categorizedRawCredentials.map(async (crc) => {
					const issuer = issuersConfigurations.get(crc.credentialIssuerIdentifier);
					const supportedCredential = issuer?.supportedCredentials.filter(sc => sc.getId() == crc.supportedCredentialIdentifier)[0];
					if (!supportedCredential) {
						return;
					}
					if (crc.issuanceFlow == IssuanceFlow.IN_TIME) {
						await this.credentialPoolService.storeInReadyCredentialsPoolInTime(access_token, crc.supportedCredentialIdentifier, { acceptance_token: "", rawCredential: crc, supportedCredential: supportedCredential});
						console.log("Raw cred = ",crc )
						console.log("supported cred = ", supportedCredential)
						console.log("Stored in ready credential pool")
					}
					else if (crc.issuanceFlow == IssuanceFlow.DEFERRED) {
						const acceptance_token = randomUUID();
						await redisModule.storeAcceptanceToken(acceptance_token, (userSession as UserSession).id);
						await this.credentialPoolService.storeInPendingCredentialsPoolDeferred(access_token, crc.supportedCredentialIdentifier, {
							acceptance_token: acceptance_token,
							rawCredential: crc,
							supportedCredential: supportedCredential
						});
					}
				}));
			}
			catch (err) {
				console.error("Error = ", err)
				res.status(500).json({ error: "Failed"})
				return
			}
			break;
		case GrantType.PRE_AUTHORIZED_CODE:
			body = tokenRequestBodySchemaForPreAuthorizedCodeGrant.parse(req.body);
			let userSession = (await redisModule.getSessionByPreAuthorizedCode(body["pre-authorized_code"], body.user_pin ? body.user_pin : "")).unwrapOr(null);
			if (!userSession)
				throw new Error("Could not get session");
			if (!userSession.categorizedRawCredentials) {
				await loadCategorizedRawCredentialsToUserSession(req, userSession.id);
				userSession = await redisModule.getUserSession(userSession.id);
				if (!userSession)
					throw new Error("Could not get session");
			}
			if (!userSession.categorizedRawCredentials)
				throw new Error("Could not get categorized raw credential after loading");

			response = await preAuthorizedCodeGrantTokenEndpoint(body);
			{
				const { access_token } = response
				await Promise.all(userSession.categorizedRawCredentials.map(async (crc) => {
					const issuer = issuersConfigurations.get(crc.credentialIssuerIdentifier);
					const supportedCredential = issuer?.supportedCredentials.filter(sc => sc.getId() == crc.supportedCredentialIdentifier)[0];
					if (!supportedCredential) {
						return;
					}
					if (crc.issuanceFlow == IssuanceFlow.IN_TIME) {
						await this.credentialPoolService.storeInReadyCredentialsPoolInTime(access_token, crc.supportedCredentialIdentifier, { acceptance_token: "", rawCredential: crc, supportedCredential: supportedCredential});
						console.log("Raw cred = ",crc )
						console.log("supported cred = ", supportedCredential)
						console.log("Stored in ready credential pool")
					}
					else if (crc.issuanceFlow == IssuanceFlow.DEFERRED) {
						const acceptance_token = randomUUID();
						await redisModule.storeAcceptanceToken(acceptance_token, (userSession as UserSession).id);
						await this.credentialPoolService.storeInPendingCredentialsPoolDeferred(access_token, crc.supportedCredentialIdentifier, {
							acceptance_token: acceptance_token,
							rawCredential: crc,
							supportedCredential: supportedCredential
						});
					}
				}));
			}

			break;
		default:
			console.log("Grant type is not supported");
			res.status(400).send("Granttype not supported");
			return;
			// body = tokenRequestBodySchemaForPreAuthorizedCodeGrant.parse(req.body);
			// response = await preAuthorizedCodeGrantTokenEndpoint(body);
			// break;
		}
		res.setHeader("Cache-Control", "no-store");
		res.json(response);
	}

	private async verifyAccessToken(req: Request, res: Response): Promise<boolean> {
		console.log("Access token verification")
		if (!req.headers.authorization) {
			console.log("no authorization token found")
			res.status(500).send({})
			return false;
		}
		const access_token = req.headers.authorization.split(' ')[1];
	
		const sessionRes = await redisModule.getSessionByAccessToken(access_token);
		if (sessionRes.err) {
			switch (sessionRes.val) {
			case "KEY_NOT_FOUND":
				console.log("Key not found")
				res.status(401).send({});
				return false;
			case "REDIS_ERR":
	
				console.log('Redis err');
				res.status(500).send({});
				return false;
			}
		}
		req.userSession = sessionRes.unwrap();
		return true;
	}

	async credentialRequestHandler(req: Request, res: Response): Promise<void> {
		if (!(await this.verifyAccessToken(req, res))) {
			return;
		}

		const access_token = req.headers.authorization?.split(' ')[1] as string;

		console.log('Hello')
		try {
			if (!req.userSession) {
				throw 'No user session exists';
			}
			const response = await this.returnSingleCredential(req.userSession, access_token, req.body as CredentialRequestBody)
			res.send(response);
		}
		catch(err) {
			console.log("Error: ", err);
			res.status(500).send({});
		}
	}

	async batchCredentialRequestHandler(req: Request, res: Response): Promise<void> {
		if (!(await this.verifyAccessToken(req, res))) {
			return;
		}
		const access_token = req.headers.authorization?.split(' ')[1] as string;
		try {
			if (!req.userSession) {
				throw 'No user session exists';
			}
			const requests: CredentialRequestBody[] = req.body.credential_requests as CredentialRequestBody[];
			const responsePromises = [];
			for (const credReq of requests) {
				responsePromises.push(this.returnSingleCredential(req.userSession, access_token, credReq as CredentialRequestBody));
			}
			const responses = await Promise.all(responsePromises);
			res.send({ credential_responses: responses });
		}
		catch(err) {
			console.log("Error: ", err);
			res.status(500).send({});
		}
	}

	async deferredCredentialRequestHandler(req: Request, res: Response): Promise<void> {
		const acceptance_token = req.headers.authorization?.split(' ')[1] as string;
		try {
			const session = (await redisModule.getSessionByAcceptanceToken(acceptance_token)).unwrap();
			const item = await this.credentialPoolService.getFromReadyCredentialsPoolDeferred(acceptance_token);
			if (!item) {
				console.log("Error: No credential to be returned");
				res.status(500).send({});
				return;
			}
			const { format, credential } = await item.supportedCredential.generateCredentialResponse(session, session.authorizationReqParams?.client_id as string);
			res.send({ format, credential });
		}
		catch(err) {
			console.log("Error: ", err);
			res.status(500).send({});
		}
	}

	/**
	 * @throws
	 * @param userSession 
	 * @param credentialRequest 
	 * @returns 
	 */
	private async returnSingleCredential(userSession: UserSession, access_token: string, credentialRequest: CredentialRequestBody): Promise<{ acceptance_token?: string, credential?: any, format?: string }> {
		console.log("Credential request = ", credentialRequest)
		let body: CredentialRequestBody;
		try {
			body = credentialRequestBodySchema.parse(credentialRequest);
		}
		catch(e) {
			console.log("invalid request body schema");
			throw 'Invalid request body'
		}
	
		// check proof
		const proof = body.proof;
		if (!proof) {
			throw 'no proof found'
		}
	
	
		const associatedAuthorizationDetail = userSession.authorizationDetails?.filter(ad => 
			ad.format == credentialRequest.format &&
			_.isEqual(ad.types, credentialRequest.types))[0];
		
		if (!associatedAuthorizationDetail?.locations ||
			!Array.isArray(associatedAuthorizationDetail.locations) ||
			associatedAuthorizationDetail.locations.length != 1) {
			
			throw "No location is given or invalid location on Authorization Details"
		}
		const credentialIssuerIdentifier = associatedAuthorizationDetail.locations[0];
		// WARNING: temporarily only the first credential is selected
		// After changing the OpenID4VCI spec, this endpoint must be changed.
		console.log("Raw creds = ", userSession.categorizedRawCredentials)
		// const credentialIssuerIdentifier = userSession.categorizedRawCredentials
		// 	.filter(crc => userSession?.selectedCredentialIdList && crc.credential_id == userSession?.selectedCredentialIdList[0])[0].credentialIssuerIdentifier;
		console.log("Credential issuer identifier = ", credentialIssuerIdentifier)
		// const authzDetails: AuthorizationDetail[] = JSON.parse(req.access_token_data.authzRequestData.authorizationReqParams.authorization_details);
		const { did } = await verifyProof(proof, userSession);
	
	
		if (!userSession.authorizationDetails) {
			throw 'No authorization details found'
		}
		const matched = userSession.authorizationDetails.filter((ad) => ad.format === body.format && _.isEqual(ad.types, body.types));
		if (matched.length == 0) { // this access token is not authorized to access this credential (format, types)
			throw "No authorized for this (types, format)"
		}
	
	
		const issuer = issuersConfigurations.get(credentialIssuerIdentifier);
		console.log("Issuer = ", issuer)
		if (!issuer) {
			throw "Issuer not found"
		}
	

		const resolvedSupportedCredential = issuer.supportedCredentials
			.filter(sc => 
				sc.getFormat() == body.format && 
				_.isEqual(sc.getTypes(), body.types)
			)[0];

		if (!resolvedSupportedCredential) {
			throw new Error("Credential could not be resolved");
		}

		try {
			const deferredCred = await this.credentialPoolService.getFromPendingCredentialsPoolDeferred(access_token, resolvedSupportedCredential.getId());
			if (deferredCred) {
				setTimeout(() => {
					this.credentialPoolService.moveFromPendingToReadyDeferred(access_token, resolvedSupportedCredential.getId(), { firstName: "XXX", familyName: "YYY" });
					console.log("Moved from pending to deferred");
				}, 5000);
				return { acceptance_token: deferredCred.acceptance_token };
			}
			
			// sign ...
			const intimeCred = await this.credentialPoolService.getFromReadyCredentialsPoolInTime(access_token, resolvedSupportedCredential.getId());
			if (!intimeCred) {
				throw new Error("In time credential could not be returned");
			}
			// sign item
			const { format, credential } = await resolvedSupportedCredential.generateCredentialResponse(userSession, did);
			const credentialResponse = { format: format, credential: credential };
			console.log("Credential response = ", credentialResponse)
			return credentialResponse;
		}
		catch(e) {
			throw new Error("Credential could not be returned. Error: " + e);
		}

	}

}