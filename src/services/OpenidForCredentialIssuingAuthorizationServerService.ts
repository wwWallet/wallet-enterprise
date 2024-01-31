import { Request, Response } from "express";
import { CredentialIssuersConfiguration, OpenidForCredentialIssuingAuthorizationServerInterface, OpenidForPresentationsReceivingInterface } from "./interfaces";
import { AuthorizationDetailsSchemaType, CredentialSupported, GrantType, authorizationDetailsSchema, authorizationRequestQueryParamsSchema, tokenRequestBodySchemaForAuthorizationCodeGrant, tokenRequestBodySchemaForPreAuthorizedCodeGrant } from "../types/oid4vci";
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
import { REQUIRE_PIN } from "../configuration/consent/consent.config";


@injectable()
export class OpenidForCredentialIssuingAuthorizationServerService implements OpenidForCredentialIssuingAuthorizationServerInterface {
	
	private authorizationServerStateRepository: Repository<AuthorizationServerState> = AppDataSource.getRepository(AuthorizationServerState);

	/**
	 * scope which will be used for the verification of the user if VP token is used as an authentication mechanism
	*/
	private readonly verificationScopeName = "vid";
	
	constructor(
		@inject(TYPES.CredentialIssuersConfiguration) private credentialIssuersConfiguration: CredentialIssuersConfiguration,
		@inject(TYPES.OpenidForPresentationsReceivingService) private openidForPresentationReceivingService: OpenidForPresentationsReceivingInterface,
	) { }

	metadataRequestHandler(): Promise<void> {
		throw new Error("Method not implemented.");
	}


	async generateCredentialOfferURL(ctx: { req: Request, res: Response }, credentialSupported: CredentialSupported): Promise<{ url: URL, user_pin_required: boolean, user_pin: string | undefined }> {

		// force creation of new state with a separate pre-authorized_code which has specific scope
		let newAuthorizationServerState: AuthorizationServerState = { ...ctx.req.authorizationServerState, id: 0 } as AuthorizationServerState;
		newAuthorizationServerState.user_pin_required = false;
		newAuthorizationServerState.pre_authorized_code = crypto.randomBytes(60).toString('base64url');
		newAuthorizationServerState.authorization_details = [
			{ types: credentialSupported.types as string[], format: credentialSupported.format, type: 'openid_credential' }
		];

		newAuthorizationServerState.user_pin_required = false;

		if (REQUIRE_PIN) {
			newAuthorizationServerState.user_pin_required = true;
			newAuthorizationServerState.user_pin = Math.floor(1000 + Math.random() * 9000).toString();
		}

		const insertRes = await this.authorizationServerStateRepository.insert(newAuthorizationServerState);
		console.log("Insertion result = ", insertRes);

		const credentialOffer = {
			credential_issuer: newAuthorizationServerState.credential_issuer_identifier ??
				this.credentialIssuersConfiguration.defaultCredentialIssuerIdentifier(),
			credentials: [
				{
					types: credentialSupported.types,
					format: credentialSupported.format
				}
			],
			grants: {
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					"pre-authorized_code": newAuthorizationServerState.pre_authorized_code,
					"user_pin_required": newAuthorizationServerState.user_pin_required
				}
			}
		};
		const redirect_uri = ctx.req?.authorizationServerState.redirect_uri ?? "openid-credential-offer://";
		const credentialOfferURL = new URL(redirect_uri);
		credentialOfferURL.searchParams.append('credential_offer', JSON.stringify(credentialOffer));
		
		console.log("Credential offer = ", credentialOfferURL)
		return {
			url: credentialOfferURL,
			user_pin_required: newAuthorizationServerState.user_pin_required,
			user_pin: newAuthorizationServerState.user_pin
		};
	}


	/**
	 * Updates the authorization server state on Database entity and on Session
	 * @param ctx 
	 * @param newAuthorizationServerState 
	 * @returns 
	 */
	private async updateAuthorizationServerState(ctx: {req: Request, res: Response}, newAuthorizationServerState: AuthorizationServerState): Promise<{ newStateRecord: AuthorizationServerState }> {
		const insertedState = await this.authorizationServerStateRepository.save(newAuthorizationServerState); // update session on database
		ctx.req.session.authorizationServerStateIdentifier = insertedState.id; // update state identifier on session
		return { newStateRecord: insertedState };
	}


	async authorizationRequestHandler(ctx: { req: Request, res: Response }): Promise<void> {
		ctx.req.session.authenticationChain = {}; // clear the session

		const params = authorizationRequestQueryParamsSchema.parse(ctx.req.query);
		if (!params.authorization_details) {
			ctx.res.status(400).send({ error: "Authorization Details is missing" })
			return
		}
	
		console.log("Authorization details = ", params.authorization_details)
		const { success } = authorizationDetailsSchema.safeParse(JSON.parse(params.authorization_details))
		if (!success) {
			console.error({ error: "Invalid authorization details" });
			ctx.res.status(400).send({ error: "Invalid authorization details" });
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
		newAuthorizationServerState.grant_type = GrantType.AUTHORIZATION_CODE;

		if (authorizationDetails[0] && authorizationDetails[0].locations 
				&& authorizationDetails[0].locations[0]) {
			newAuthorizationServerState.credential_issuer_identifier = authorizationDetails[0].locations[0];
		}
		else {
			const defaultCredentialIssuerIdentifier = this.credentialIssuersConfiguration.defaultCredentialIssuerIdentifier();
			if (!defaultCredentialIssuerIdentifier) {
				throw new Error("Credential issuer could not be resolved because no default issuer exists and issuer is not specified on location of authorization details");
			}
			newAuthorizationServerState.credential_issuer_identifier = defaultCredentialIssuerIdentifier;
		}
		
		// if VP token auth is used, then use the verificationScopeName constant to verify the client
		if (DID_AUTHENTICATION_MECHANISM_USED == DIDAuthenticationMechanism.OPENID4VP_VP_TOKEN) {
			newAuthorizationServerState.scope = params.scope + ' ' + this.verificationScopeName;
			ctx.req.query.scope += newAuthorizationServerState.scope;
		}

		const { newStateRecord } = await this.updateAuthorizationServerState(ctx, newAuthorizationServerState)

		let redirected = false;
		(ctx.res.redirect as any) = (url: string): void => {
			redirected = true;
			// Perform the actual redirect
			ctx.res.location(url);
			ctx.res.statusCode = 302;
			ctx.res.end();
		};
		
		console.log("Did auth mechanism = ", DID_AUTHENTICATION_MECHANISM_USED)
		
		if (DID_AUTHENTICATION_MECHANISM_USED == DIDAuthenticationMechanism.OPENID4VP_ID_TOKEN ||
				DID_AUTHENTICATION_MECHANISM_USED == DIDAuthenticationMechanism.OPENID4VP_VP_TOKEN) {
	
			await this.openidForPresentationReceivingService.authorizationRequestHandler(ctx, newStateRecord.id);
			if (redirected) {
				return;
			}
			console.log("did not redirect");
			return;
		}
		else {
			console.log("Redirecting...")
			ctx.res.redirect(CONSENT_ENTRYPOINT);
			return;
		}
	}

	async sendAuthorizationResponse(ctx: { req: Request, res: Response }, bindedUserSessionId: number, authorizationDetails?: AuthorizationDetailsSchemaType): Promise<void> {
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

		ctx.res.redirect(authorizationResponseURL.toString());
	}


	async tokenRequestHandler(ctx: { req: Request, res: Response }): Promise<void> {
		console.log("Body ", ctx.req.body)

		let body = null;
		let response = { };
		if (!ctx.req.body.grant_type) {
			console.log("No grant type was found");
			ctx.res.status(500).send({});
			return;
		}
	
		switch (ctx.req.body.grant_type) {
		case GrantType.AUTHORIZATION_CODE:
			body = tokenRequestBodySchemaForAuthorizationCodeGrant.parse(ctx.req.body);
			// if (!ctx.req.headers.authorization) {
			// 	return ctx.res.status(401).send("No authorization header was provided");
			// }
			try {

				let state = await this.authorizationServerStateRepository.createQueryBuilder("state")
					.where("state.authorization_code = :code", { code: body.code })
					.getOne();

				if (!state)
					throw new Error("Could not get session");

				state.authorization_code = null; // invalidate the authorization code
				await this.authorizationServerStateRepository.save(state);
				// if (!userSession.categorizedRawCredentials) {
				// 	userSession = await redisModule.getUserSession(userSession.id);
				// 	if (!userSession)
				// 		throw new Error("Could not get session");
				// }
				// if (!userSession.categorizedRawCredentials)
				// 	throw new Error("Could not get categorized raw credential");
				response = await authorizationCodeGrantTokenEndpoint(state, ctx.req.headers.authorization);
			}
			catch (err) {
				console.error("Error = ", err)
				ctx.res.status(500).json({ error: "Failed"})
				return
			}
			break;
		case GrantType.PRE_AUTHORIZED_CODE:
			try {
				body = tokenRequestBodySchemaForPreAuthorizedCodeGrant.parse(ctx.req.body);
				if (body["pre-authorized_code"] == 'undefined') {
					throw new Error("Pre authorized code is undefined");
				}
				let state = await this.authorizationServerStateRepository
					.createQueryBuilder("state")
					.where("state.pre_authorized_code = :code", { code: body["pre-authorized_code"] })
					.getOne();
				if (!state) {
					throw new Error(`No authorization server state was found for authorization code ${body["pre-authorized_code"]}`);
				}
				// compare pin
				if (state.user_pin_required &&
						state.user_pin_required == true &&
						body.user_pin != undefined &&
						body.user_pin !== state.user_pin) {
					
					response = { ...response, error_description: "Invalid pin" }
					throw new Error("Invalid PIN was given");
				}
				state.pre_authorized_code = null; // invalidate the pre-authorized code to prevent reuse
				await AppDataSource.getRepository(AuthorizationServerState).save(state);

				console.log("State on token req = ", state);
				response = await preAuthorizedCodeGrantTokenEndpoint(state);
			}
			catch(err) {
				console.log("Error on token request pre authorized code")
				console.log(err);
				ctx.res.status(500).json({ error: "ERROR", ...response });
				return;
			}
			break;
		default:
			console.log("Grant type is not supported");
			ctx.res.status(400).send("Granttype not supported");
			return;
			// body = tokenRequestBodySchemaForPreAuthorizedCodeGrant.parse(ctx.req.body);
			// response = await preAuthorizedCodeGrantTokenEndpoint(body);
			// break;
		}
		ctx.res.setHeader("Cache-Control", "no-store");
		ctx.res.json(response);
	}

}