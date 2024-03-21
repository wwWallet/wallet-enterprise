import { Request, Response } from "express";
import { CredentialIssuersConfiguration, OpenidForCredentialIssuingAuthorizationServerInterface } from "./interfaces";
import { AuthorizationDetailsSchemaType, CredentialSupported, GrantType } from "../types/oid4vci";
import { inject, injectable } from "inversify";
import { TYPES } from "./types";
import crypto from 'node:crypto';
import _ from "lodash";
import 'reflect-metadata';
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
import AppDataSource from "../AppDataSource";
import { Repository } from "typeorm";
import { CONSENT_ENTRYPOINT } from "../authorization/constants";
import { generateAccessToken } from "../openid4vci/utils/generateAccessToken";
import { REQUIRE_PIN } from "../configuration/consent/consent.config";


@injectable()
export class OpenidForCredentialIssuingAuthorizationServerService implements OpenidForCredentialIssuingAuthorizationServerInterface {
	
	private authorizationServerStateRepository: Repository<AuthorizationServerState> = AppDataSource.getRepository(AuthorizationServerState);

	
	constructor(
		@inject(TYPES.CredentialIssuersConfiguration) private credentialIssuersConfiguration: CredentialIssuersConfiguration,
	) { }

	metadataRequestHandler(): Promise<void> {
		throw new Error("Method not implemented.");
	}


	async generateCredentialOfferURL(ctx: { req: Request, res: Response }, credentialSupported: CredentialSupported, grantType: GrantType, issuerState?: string): Promise<{ url: URL, user_pin_required?: boolean, user_pin?: string | undefined }> {

		// force creation of new state with a separate pre-authorized_code which has specific scope
		let newAuthorizationServerState: AuthorizationServerState = { ...ctx.req.authorizationServerState, id: 0 } as AuthorizationServerState;
		if (grantType == GrantType.PRE_AUTHORIZED_CODE) {
			newAuthorizationServerState.user_pin_required = false;
			newAuthorizationServerState.pre_authorized_code = crypto.randomBytes(60).toString('base64url');
			if (REQUIRE_PIN) {
				newAuthorizationServerState.user_pin_required = true;
				newAuthorizationServerState.user_pin = Math.floor(1000 + Math.random() * 9000).toString();
			}
		}

		newAuthorizationServerState.authorization_details = [
			{ types: credentialSupported.types as string[], format: credentialSupported.format, type: 'openid_credential' }
		];



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
			grants: { }
		};

		if (grantType == GrantType.PRE_AUTHORIZED_CODE) {
			credentialOffer.grants = {
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					"pre-authorized_code": newAuthorizationServerState.pre_authorized_code,
					"user_pin_required": newAuthorizationServerState.user_pin_required
				}
			}
		}
		else { // authorization code grant type
			if (issuerState) { // if issuer state was provided
				credentialOffer.grants = {
					authorization_code: {
						issuer_state: issuerState
					}
				};
			}
			else {
				credentialOffer.grants = {
					authorization_code: { }
				};
			}
		}
		
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


	private async updateAuthorizationServerState(ctx: {req: Request, res: Response}, newAuthorizationServerState: AuthorizationServerState): Promise<{ newStateRecord: AuthorizationServerState }> {
		const insertedState = await this.authorizationServerStateRepository.save(newAuthorizationServerState); // update session on database
		ctx.req.session.authorizationServerStateIdentifier = insertedState.id; // update state identifier on session
		return { newStateRecord: insertedState };
	}


	async authorizationRequestPKCEHandler(ctx: {req: Request, res: Response}) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}
		ctx.req.authorizationServerState.code_challenge = ctx.req.query.code_challenge as string ?? null;
		ctx.req.authorizationServerState.code_challenge_method = ctx.req.query.code_challenge_method as string ?? null;
	}

	async authorizationRequestClientIdAndRedirectUriHandler(ctx: {req: Request, res: Response}) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}
		ctx.req.authorizationServerState.client_id = ctx.req.query.client_id as string ?? null;
		ctx.req.authorizationServerState.redirect_uri = ctx.req.query.redirect_uri as string ?? null;
	}

	async authorizationRequestGrantTypeHandler(ctx: {req: Request, res: Response}) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}
		ctx.req.authorizationServerState.grant_type = GrantType.AUTHORIZATION_CODE;
	}

	async authorizationRequestResponseTypeHandler(ctx: {req: Request, res: Response}) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}
		ctx.req.authorizationServerState.response_type = ctx.req.query.response_type as string ?? null;
	}

	async authorizationRequestAuthorizationDetailsHandler(ctx: {req: Request, res: Response}) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}

		console.log("Authz details = ", ctx.req.query.authorization_details)
		if (!ctx.req.query.authorization_details || typeof ctx.req.query.authorization_details != 'string') {
			ctx.res.status(400).send({ error: "'authorization_details' parameter is missing" });
			return;
		}
		try {
			ctx.req.authorizationServerState.authorization_details = JSON.parse(ctx.req.query.authorization_details) as any;
		}
		catch (e) {
			ctx.res.status(400).send({ error: "'authorization_details' parameter could not be parsed" });
			return
		}

		if (!ctx.req.authorizationServerState.authorization_details) {
			ctx.res.status(400).send({ error: "Authorization details failed to be initialized" });
			return;
		}

		if (ctx.req.authorizationServerState.authorization_details[0] && ctx.req.authorizationServerState.authorization_details[0].locations 
			&& ctx.req.authorizationServerState.authorization_details[0].locations[0]) {
				ctx.req.authorizationServerState.credential_issuer_identifier = ctx.req.authorizationServerState.authorization_details[0].locations[0];
		}
		else {
			const defaultCredentialIssuerIdentifier = this.credentialIssuersConfiguration.defaultCredentialIssuerIdentifier();
			if (!defaultCredentialIssuerIdentifier) {
				throw new Error("Credential issuer could not be resolved because no default issuer exists and issuer is not specified on location of authorization details");
			}
			ctx.req.authorizationServerState.credential_issuer_identifier = defaultCredentialIssuerIdentifier;
		}
	}

	async authorizationRequestHandler(ctx: {req: Request, res: Response}): Promise<void> {
		ctx.req.session.authenticationChain = {}; // clear the session
		await this.authorizationRequestClientIdAndRedirectUriHandler(ctx);
		await this.authorizationRequestPKCEHandler(ctx);
		await this.authorizationRequestGrantTypeHandler(ctx);
		await this.authorizationRequestResponseTypeHandler(ctx);
		await this.authorizationRequestAuthorizationDetailsHandler(ctx);
		await this.updateAuthorizationServerState(ctx, ctx.req.authorizationServerState)
		ctx.res.redirect(CONSENT_ENTRYPOINT);
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

	async tokenRequestGrantTypeHandler(ctx: { req: Request, res: Response }): Promise<void> {
		if (ctx.res.headersSent) {
			return;
		}

		switch (ctx.req.body.grant_type) {
		case GrantType.AUTHORIZATION_CODE:
			break;
		case GrantType.PRE_AUTHORIZED_CODE:
			break;
		default:
			ctx.res.status(400).send({ error: `grant_type '${ctx.req.body.grant_type}' is not supported` })
			return;
		}
	}

	async tokenRequestAuthorizationCodeHandler(ctx: { req: Request, res: Response }): Promise<void> {
		if (ctx.res.headersSent) {
			return;
		}

		if (ctx.req.body.grant_type != GrantType.AUTHORIZATION_CODE) {
			return; // this is not a job for this handler, let the other ones to decide on the request
		}
	
		if (!ctx.req.body.code) {
			ctx.res.status(400).send({ error: `the 'code' parameter is missing`})
			return;
		}

		let state = await this.authorizationServerStateRepository.createQueryBuilder("state")
			.where("state.authorization_code = :code", { code: ctx.req.body.code })
			.getOne();
		if (!state) {
			ctx.res.status(400).send({ error: `the authorization code ${ctx.req.body.code} does not exist` });
			return;
		}

		state.authorization_code = null; // invalidate the authorization code
		await this.authorizationServerStateRepository.save(state);
		ctx.req.authorizationServerState = state;
	}

	async tokenRequestPreAuthorizedCodeHandler(ctx: { req: Request, res: Response }): Promise<void> {
		if (ctx.res.headersSent) {
			return;
		}
		if (ctx.req.body.grant_type != GrantType.PRE_AUTHORIZED_CODE) {
			return;
		}
		if (!ctx.req.body['pre-authorized_code']) {
			ctx.res.status(400).send({ error: `the 'pre-authorized_code' parameter is missing` })
			return;
		}

		let state = await this.authorizationServerStateRepository.createQueryBuilder("state")
			.where("state.pre_authorized_code = :code", { code: ctx.req.body['pre-authorized_code'] })
			.getOne();
		if (!state) {
			ctx.res.status(400).send({ error: `pre-authorized_code ${ctx.req.body['pre-authorized_code']} does not exist` });
			return;
		}

		state.pre_authorized_code = null; // invalidate the pre-authorized code
		await this.authorizationServerStateRepository.save(state);
		ctx.req.authorizationServerState = state;
	}

	async tokenRequestUserPinHandler(ctx: { req: Request, res: Response }): Promise<void> {
		if (ctx.res.headersSent) {
			return;
		}

		if (ctx.req.body.grant_type != GrantType.PRE_AUTHORIZED_CODE) {
			return;
		}

		if (!ctx.req.body.user_pin) {
			ctx.res.status(400).send({ error: `user_pin parameter is missing` });
			return;
		}

		if (!ctx.req?.authorizationServerState?.user_pin) {
			ctx.res.status(400).send({ error: `user_pin is not defined on state` });
			return;
		}

		if (ctx.req?.authorizationServerState?.user_pin != ctx.req.body.user_pin) {
			ctx.res.status(400).send({ error: "invalid_request", error_description: "INVALID_PIN" });
			return;
		}
	}

	async tokenRequestHandler(ctx: { req: Request, res: Response }): Promise<void> {
		ctx.res.setHeader("Cache-Control", "no-store");
		await this.tokenRequestGrantTypeHandler(ctx);
		await this.tokenRequestAuthorizationCodeHandler(ctx);
		await this.tokenRequestPreAuthorizedCodeHandler(ctx);
		// await this.tokenRequestUserPinHandler(ctx); keep this commented to not require userpin

		const response = await generateAccessToken(ctx.req.authorizationServerState);
		ctx.res.send(response);
	}

}