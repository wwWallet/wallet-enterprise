import { Request, Response } from "express";
import { OpenidForCredentialIssuingAuthorizationServerInterface, OpenidForPresentationsReceivingInterface } from "./interfaces";
import { AuthorizationDetailsSchemaType, GrantType, authorizationDetailsSchema, authorizationRequestQueryParamsSchema, tokenRequestBodySchemaForAuthorizationCodeGrant, tokenRequestBodySchemaForPreAuthorizedCodeGrant } from "../types/oid4vci";
import { DID_AUTHENTICATION_MECHANISM_USED, DIDAuthenticationMechanism } from "../configuration/authentication/auth.config";
import { inject, injectable } from "inversify";
import { TYPES } from "./types";
import { CONSENT_ENTRYPOINT } from "../authorization/constants";
import crypto from 'node:crypto';
import { authorizationCodeGrantTokenEndpoint } from "../openid4vci/grant_types/AuthorizationCodeGrant";
import _ from "lodash";
import 'reflect-metadata';
import { preAuthorizedCodeGrantTokenEndpoint } from "../openid4vci/grant_types/PreAuthorizedCodeGrant";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
import AppDataSource from "../AppDataSource";
import { Repository } from "typeorm";
import { storeAuthorizationServerStateIdToWebClient } from "../middlewares/authorizationServerState.middleware";


@injectable()
export class OpenidForCredentialIssuingAuthorizationServerService implements OpenidForCredentialIssuingAuthorizationServerInterface {
	
	private authorizationServerStateRepository: Repository<AuthorizationServerState> = AppDataSource.getRepository(AuthorizationServerState);

	/**
	 * scope which will be used for the verification of the user if VP token is used as an authentication mechanism
	*/
	private readonly verificationScopeName = "vid";
	
	constructor(
		@inject(TYPES.OpenidForPresentationsReceivingService) private openidForPresentationReceivingService: OpenidForPresentationsReceivingInterface,
	) { }

	metadataRequestHandler(_req: Request, _res: Response): Promise<void> {
		throw new Error("Method not implemented.");
	}


	async authorizationRequestHandler(req: Request, res: Response): Promise<void> {
		const params = authorizationRequestQueryParamsSchema.parse(req.query);
		if (!params.authorization_details) {
			res.status(400).send({ error: "Authorization Details is missing" })
			return
		}
	
		console.log("Authorization details = ", params.authorization_details)
		const { success } = authorizationDetailsSchema.safeParse(JSON.parse(params.authorization_details))
		if (!success) {
			console.error({ error: "Invalid authorization details" });
			res.status(400).send({ error: "Invalid authorization details" });
			return;
		}
		const authorizationDetails = JSON.parse(params.authorization_details) as AuthorizationDetailsSchemaType;
	
		// TODO: make sure that authorization details are correct and conform to the ones publish on the CredentialIssuerMetadata
		// TODO: make sure that the client_id exists in the clients table
	

		const newAuthorizationServerState = new AuthorizationServerState();
		newAuthorizationServerState.authorization_details = authorizationDetails;
		newAuthorizationServerState.client_id = params.client_id;
		newAuthorizationServerState.code_challenge = params.code_challenge;
		newAuthorizationServerState.code_challenge_method = params.code_challenge_method;
		newAuthorizationServerState.response_type = params.response_type;
		newAuthorizationServerState.redirect_uri = params.redirect_uri;
		newAuthorizationServerState.scope = params.scope;

		// if VP token auth is used, then use the verificationScopeName constant to verify the client
		if (DID_AUTHENTICATION_MECHANISM_USED == DIDAuthenticationMechanism.OPENID4VP_VP_TOKEN) {
			newAuthorizationServerState.scope = params.scope + ' ' + this.verificationScopeName;
			req.query.scope += newAuthorizationServerState.scope;
		}

	
		console.log("Authz server state = ", newAuthorizationServerState)
		const insertedState = await this.authorizationServerStateRepository.save(newAuthorizationServerState);
		await storeAuthorizationServerStateIdToWebClient(res, insertedState.id); // now it has been assigned a new state id
	
		let redirected = false;
		(res.redirect as any) = (url: string): void => {
			redirected = true;
			// Perform the actual redirect
			res.location(url);
			res.statusCode = 302;
			res.end();
		};
		
		console.log("Did auth mechanism = ", DID_AUTHENTICATION_MECHANISM_USED)
		
		if (DID_AUTHENTICATION_MECHANISM_USED == DIDAuthenticationMechanism.OPENID4VP_ID_TOKEN ||
				DID_AUTHENTICATION_MECHANISM_USED == DIDAuthenticationMechanism.OPENID4VP_VP_TOKEN) {
	
			await this.openidForPresentationReceivingService.authorizationRequestHandler(req, res, insertedState.id);
			if (redirected) {
				return;
			}
			console.log("did not redirect");
			return;
		}
		else {
			console.log("Redirecting...")
			res.redirect(CONSENT_ENTRYPOINT);
			return;
		}
	}

	async sendAuthorizationResponse(_req: Request, res: Response, bindedUserSessionId: number, authorizationDetails?: AuthorizationDetailsSchemaType): Promise<void> {
		const stateId = bindedUserSessionId;

		const state = await this.authorizationServerStateRepository.createQueryBuilder("state")
			.where("state.id = :id", { id: stateId })
			.getOne();

		console.log("State on the authorization response = ", state)

		if (!state) {
			const msg = { error: "Unable to send authorization response", error_description: "No issuanceState was found for this user session id"};
			console.error(msg);
			throw new Error(JSON.stringify(msg));
		}


		if (!state.client_id) {
			throw new Error("Error on sendAuthorizationResponse(): No client id was defined on the authorization request");
		}
	
		if (!state.redirect_uri) {
			throw new Error("Redirect uri not found in params");
		}

		
		const authorization_code = crypto.randomBytes(60).toString('base64url');
		state.authorization_code = authorization_code;
		if (authorizationDetails)
			state.authorization_details = authorizationDetails;

		const authorizationResponseURL = new URL(state.redirect_uri);
		authorizationResponseURL.searchParams.append("code", authorization_code);
		
		if (state.state) {
			authorizationResponseURL.searchParams.append("state", state.state);
		}

		await this.authorizationServerStateRepository.save(state);

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

				let state = await this.authorizationServerStateRepository.createQueryBuilder("state")
					.where("state.authorization_code = :code", { code: body.code })
					.getOne();

				if (!state)
					throw new Error("Could not get session");
				// if (!userSession.categorizedRawCredentials) {
				// 	userSession = await redisModule.getUserSession(userSession.id);
				// 	if (!userSession)
				// 		throw new Error("Could not get session");
				// }
				// if (!userSession.categorizedRawCredentials)
				// 	throw new Error("Could not get categorized raw credential");
				response = await authorizationCodeGrantTokenEndpoint(body, req.headers.authorization);
			}
			catch (err) {
				console.error("Error = ", err)
				res.status(500).json({ error: "Failed"})
				return
			}
			break;
		case GrantType.PRE_AUTHORIZED_CODE:
			body = tokenRequestBodySchemaForPreAuthorizedCodeGrant.parse(req.body);
			let state = await this.authorizationServerStateRepository.createQueryBuilder("state")
				.where("state.authorization_code = :code", { code: body["pre-authorized_code"] })
				.getOne();
			if (!state)
				throw new Error("Could not get session");
			response = await preAuthorizedCodeGrantTokenEndpoint(body);
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

}