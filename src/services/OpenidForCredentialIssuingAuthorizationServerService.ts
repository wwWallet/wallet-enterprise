import { Request, Response } from "express";
import { CredentialConfigurationRegistry, OpenidForCredentialIssuingAuthorizationServerInterface, OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "./interfaces";
import { GrantType } from "../types/oid4vci";
import { inject, injectable } from "inversify";
import crypto, { randomUUID } from 'node:crypto';
import _ from "lodash";
import 'reflect-metadata';
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
import AppDataSource from "../AppDataSource";
import { Repository } from "typeorm";
import { CONSENT_ENTRYPOINT } from "../authorization/constants";
import base64url from "base64url";
import { config } from "../../config";
import { importJWK, importX509, JWK, jwtVerify } from "jose";
import { TYPES } from "./types";
import { generateRandomIdentifier } from "../lib/generateRandomIdentifier";
import { addSessionIdCookieToResponse } from "../sessionIdCookieConfig";
import { arrayBufferToBase64Url } from "../util/arrayBufferToBase64Url";
import { verifyX5C } from "wallet-common";

// @ts-ignore
const access_token_expires_in = config.issuanceFlow.access_token_expires_in ? config.issuanceFlow.access_token_expires_in : 60; // 1 minute

// @ts-ignore
const c_nonce_expires_in = config.issuanceFlow.c_nonce_expires_in ? config.issuanceFlow.c_nonce_expires_in : 60; // 1 minute

// @ts-ignore
const refresh_token_expires_in = config.issuanceFlow.refresh_token_expires_in ? config.issuanceFlow.refresh_token_expires_in : 24 * 60 * 60; // 1 day



@injectable()
export class OpenidForCredentialIssuingAuthorizationServerService implements OpenidForCredentialIssuingAuthorizationServerInterface {

	private authorizationServerStateRepository: Repository<AuthorizationServerState> = AppDataSource.getRepository(AuthorizationServerState);

	constructor(
		@inject(TYPES.CredentialConfigurationRegistryService) private credentialConfigurationRegistryService: CredentialConfigurationRegistry,
		@inject(TYPES.OpenidForPresentationsReceivingService) private presentationReceivingService: OpenidForPresentationsReceivingInterface,
		@inject(TYPES.VerifierConfigurationServiceInterface) private verifierConfigurationService: VerifierConfigurationInterface,

	) { }

	metadataRequestHandler(): Promise<void> {
		throw new Error("Method not implemented.");
	}


	async generateCredentialOfferURL(ctx: { req: Request, res: Response }, credentialConfigurationIds: string[], issuerState?: string): Promise<{ url: URL, user_pin_required?: boolean, user_pin?: string | undefined }> {

		// force creation of new state with a separate pre-authorized_code which has specific scope
		let newAuthorizationServerState: AuthorizationServerState = { ...ctx.req.authorizationServerState, id: 0 } as AuthorizationServerState;
		newAuthorizationServerState.credential_configuration_ids = credentialConfigurationIds;


		if (issuerState) {
			newAuthorizationServerState.issuer_state = issuerState;
		}

		const insertRes = await this.authorizationServerStateRepository.insert(newAuthorizationServerState);
		console.log("Insertion result = ", insertRes);

		const credentialOffer = {
			credential_issuer: config.url,
			credential_configuration_ids: credentialConfigurationIds,
			grants: {}
		};


		if (issuerState) { // if issuer state was provided
			credentialOffer.grants = {
				authorization_code: {
					issuer_state: issuerState
				}
			};
		}
		else {
			credentialOffer.grants = {
				authorization_code: {}
			};
		}

		const redirect_uri = ctx.req?.authorizationServerState?.redirect_uri ?? config.wwwalletURL;
		const credentialOfferURL = new URL(redirect_uri);
		credentialOfferURL.searchParams.append('credential_offer', JSON.stringify(credentialOffer));

		console.log("Credential offer = ", credentialOfferURL)
		return {
			url: credentialOfferURL,
			user_pin_required: newAuthorizationServerState.user_pin_required,
			user_pin: newAuthorizationServerState.user_pin
		};
	}


	private async updateAuthorizationServerState(ctx: { req: Request, res: Response }, newAuthorizationServerState: AuthorizationServerState): Promise<{ newStateRecord: AuthorizationServerState }> {
		const insertedState = await this.authorizationServerStateRepository.save(newAuthorizationServerState); // update session on database
		ctx.req.session.authorizationServerStateIdentifier = insertedState.id; // update state identifier on session
		return { newStateRecord: insertedState };
	}


	async authorizationRequestIssuerStateHandler(ctx: { req: Request, res: Response }) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}
		if (!ctx.req.body.issuer_state) {
			return;
		}

		ctx.req.authorizationServerState.issuer_state = ctx.req.body.issuer_state as string ?? undefined;
	}

	async authorizationRequestPKCEHandler(ctx: { req: Request, res: Response }) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}
		ctx.req.authorizationServerState.code_challenge = ctx.req.body.code_challenge as string ?? null;
		ctx.req.authorizationServerState.code_challenge_method = ctx.req.body.code_challenge_method as string ?? null;
	}

	async authorizationRequestClientIdAndRedirectUriHandler(ctx: { req: Request, res: Response }) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}
		ctx.req.authorizationServerState.client_id = ctx.req.body.client_id as string ?? null;
		ctx.req.authorizationServerState.redirect_uri = ctx.req.body.redirect_uri as string ?? null;
	}

	async authorizationRequestGrantTypeHandler(ctx: { req: Request, res: Response }) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}
		ctx.req.authorizationServerState.grant_type = GrantType.AUTHORIZATION_CODE;
	}

	async authorizationRequestResponseTypeHandler(ctx: { req: Request, res: Response }) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}
		ctx.req.authorizationServerState.response_type = ctx.req.body.response_type as string ?? null;
	}

	async authorizationRequestScopeHandler(ctx: { req: Request, res: Response }) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}

		ctx.req.authorizationServerState.scope = ctx.req.body.scope;
	}

	// async authorizationRequestAuthorizationDetailsHandler(ctx: { req: Request, res: Response }) {
	// 	if (ctx.res.headersSent) {
	// 		return;
	// 	}
	// 	if (!ctx.req.authorizationServerState) {
	// 		ctx.req.authorizationServerState = new AuthorizationServerState();
	// 	}

	// 	if (ctx.req.body.authorization_details) {
	// 		const authorizationDetails = JSON.parse(ctx.req.body.authorization_details) as { type: string; credential_configuration_id: string }[];
	// 		if (authorizationDetails && authorizationDetails instanceof Array && authorizationDetails.length > 0) {
	// 			ctx.req.authorizationServerState.credential_configuration_ids = [ authorizationDetails[0].credential_configuration_id ];
	// 		}
	// 	}

	// }

	private async authorizationRequestStateHandler(ctx: { req: Request, res: Response }) {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.authorizationServerState) {
			ctx.req.authorizationServerState = new AuthorizationServerState();
		}

		ctx.req.authorizationServerState.state = ctx.req.body.state;
	}

	async authorizationRequestHandler(ctx: { req: Request, res: Response }): Promise<void> {
		ctx.req.session.authenticationChain = {}; // clear the session


		if (ctx.req.method == 'GET' && ctx.req.query.request_uri) {
			const session_id = generateRandomIdentifier(12);
			console.log("Session in on AUTHZ req = ", session_id);
			addSessionIdCookieToResponse(ctx.res, session_id);
			const state = await this.authorizationServerStateRepository.createQueryBuilder("state")
				.where("state.request_uri = :request_uri", { request_uri: ctx.req.query.request_uri })
				.getOne();

			if (!state) {
				console.error("request_uri provided could not resolve to any stored authorization server state");
				ctx.res.redirect('/');
				return;
			}

			if (state.request_uri_expiration_timestamp && state.request_uri_expiration_timestamp < Math.floor(Date.now() / 1000)) {
				console.error("request_uri is expired");
				ctx.res.redirect('/');
				return;
			}
			ctx.req.authorizationServerState = state;
			ctx.req.authorizationServerState.session_id = session_id;
			await this.updateAuthorizationServerState(ctx, ctx.req.authorizationServerState);
			ctx.res.redirect(CONSENT_ENTRYPOINT);
			return;
		}

		// the following functions will alter the ctx.req.authorizationServerState object
		await this.authorizationRequestIssuerStateHandler(ctx);
		await this.authorizationRequestClientIdAndRedirectUriHandler(ctx);
		await this.authorizationRequestPKCEHandler(ctx);
		await this.authorizationRequestGrantTypeHandler(ctx);
		await this.authorizationRequestResponseTypeHandler(ctx);
		await this.authorizationRequestStateHandler(ctx);
		await this.authorizationRequestScopeHandler(ctx);

		ctx.req.authorizationServerState.request_uri = `urn:ietf:params:oauth:request_uri:${base64url.encode(randomUUID())}`;
		ctx.req.authorizationServerState.request_uri_expiration_timestamp = Math.floor(Date.now() / 1000) + 60;
		await this.updateAuthorizationServerState(ctx, ctx.req.authorizationServerState);

		ctx.res.send({
			request_uri: ctx.req.authorizationServerState.request_uri,
			expires_in: 60,
		});
	}

	private async authorizeChallengeAuthorizationErrorResponse(ctx: { req: Request; res: Response; }): Promise<void> {
		if (ctx.res.headersSent) {
			return;
		}
		if (!ctx.req.body.presentation_during_issuance_session) {
			const session_id = "auth_session:" + base64url.encode(randomUUID());
			addSessionIdCookieToResponse(ctx.res, session_id);
			ctx.req.authorizationServerState.session_id = session_id;
			ctx.req.authorizationServerState.auth_session = session_id;

			await this.updateAuthorizationServerState(ctx, ctx.req.authorizationServerState);

			// @ts-ignore
			const preSelectedPresentationDefinitionId = config.issuanceFlow.firstPartyAppDynamicCredentialRequest.presentationDefinitionId;

			const presentationRequest = await this.presentationReceivingService.generateAuthorizationRequestURL(ctx,
				this.verifierConfigurationService.getPresentationDefinitions().filter((pd) => pd.id === preSelectedPresentationDefinitionId)[0],
				session_id);

			ctx.res.status(400).send({
				error: "insufficient_authorization",
				auth_session: ctx.req.authorizationServerState.auth_session,
				presentation: presentationRequest.url,
			})
		}
	}

	private async authorizeChallengeWithPresentationDuringIssuanceSessionResponse(ctx: { req: Request; res: Response; }): Promise<void> {
		if (ctx.res.headersSent) {
			return;
		}

		if (ctx.req.body.auth_session && ctx.req.body.presentation_during_issuance_session) {
			const result = await this.presentationReceivingService.getPresentationBySessionIdOrPresentationDuringIssuanceSession(undefined, ctx.req.body.presentation_during_issuance_session);
			if (result.status == true) {
				const authorization_code = crypto.randomBytes(60).toString('base64url');
				ctx.req.authorizationServerState.authorization_code = authorization_code;
				const presentationDefinition = this.verifierConfigurationService.getPresentationDefinitions().filter((pd) => pd.id == result.rpState.presentation_definition_id)[0];

				// @ts-ignore
				const claims = result.rpState.claims[presentationDefinition.input_descriptors[0].id];
				for (const { key, value } of claims) {
					// @ts-ignore
					ctx.req.authorizationServerState[key] = value;
				}
				console.log("Dynamic credential request Extracted Claims = ", claims)
				await this.updateAuthorizationServerState(ctx, ctx.req.authorizationServerState);

				ctx.res.status(200).send({
					authorization_code: authorization_code
				});
				return;
			}

			await this.authorizeChallengeAuthorizationErrorResponse(ctx); // back to step-1
		}
	}

	async authorizeChallengeRequestHandler(ctx: { req: Request; res: Response; }): Promise<void> {
		ctx.req.session.authenticationChain = {}; // clear the session

		await this.authorizationRequestStateHandler(ctx);
		await this.authorizationRequestScopeHandler(ctx);
		await this.authorizationRequestClientIdAndRedirectUriHandler(ctx);
		await this.authorizationRequestPKCEHandler(ctx);

		await this.authorizeChallengeAuthorizationErrorResponse(ctx); // step-1

		await this.authorizeChallengeWithPresentationDuringIssuanceSessionResponse(ctx); // step-2
	}

	async sendAuthorizationResponse(ctx: { req: Request, res: Response }, bindedUserSessionId: number): Promise<void> {
		const stateId = bindedUserSessionId;

		const state = await this.authorizationServerStateRepository.createQueryBuilder("state")
			.where("state.id = :id", { id: stateId })
			.getOne();

		console.log("State on the authorization response = ", state)

		if (!state) {
			const msg = { error: "Unable to send authorization response", error_description: "No issuanceState was found for this user session id" };
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


		const authorizationResponseURL = new URL(state.redirect_uri);
		authorizationResponseURL.searchParams.append("code", authorization_code);

		if (state.state) {
			authorizationResponseURL.searchParams.append("state", state.state);
		}

		await this.authorizationServerStateRepository.save(state);

		console.log("State before sending authorization response = ", state)
		ctx.res.redirect(authorizationResponseURL.toString());
	}

	async tokenRequestGrantTypeHandler(ctx: { req: Request, res: Response }): Promise<void> {
		if (ctx.res.headersSent) {
			return;
		}

		switch (ctx.req.body.grant_type) {
			case GrantType.AUTHORIZATION_CODE:
				console.info("===Grant type: Authorization code");
				break;
			case GrantType.PRE_AUTHORIZED_CODE:
				console.info("===Grant type: Pre-authorized code");
				break;
			case GrantType.REFRESH_TOKEN:
				console.info("===Grant type: Refresh token");
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
			ctx.res.status(400).send({ error: `the 'code' parameter is missing` })
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

	async tokenRequestCodeVerifierHandler(ctx: { req: Request, res: Response }) {
		if (ctx.res.headersSent) {
			return;
		}

		if (ctx.req.body.grant_type != GrantType.AUTHORIZATION_CODE) {
			return; // this is not a job for this handler, let the other ones to decide on the request
		}

		const { code_verifier } = ctx.req.body;
		if (!code_verifier || typeof code_verifier != 'string') {
			console.log("code_verifier is missing");
			ctx.res.status(400).send({ error: `code_verifier is missing` });
			return;
		}

		if (!ctx.req?.authorizationServerState?.code_challenge) {
			console.log("code_challenge could not be retrieved from current state");
			ctx.res.status(400).send({ error: `code_challenge could not be retrieved from current state` });
			return;
		}

		async function generateChallenge(code_verifier: string) {
			const buffer = await crypto.webcrypto.subtle.digest(
				"SHA-256",
				new TextEncoder().encode(code_verifier)
			);
			// Generate base64url string
			// btoa is deprecated in Node.js but is used here for web browser compatibility
			// (which has no good replacement yet, see also https://github.com/whatwg/html/issues/6811)
			return btoa(String.fromCharCode(...new Uint8Array(buffer)))
				.replace(/\//g, '_')
				.replace(/\+/g, '-')
				.replace(/=/g, '');
		}

		async function verifyChallenge(
			code_verifier: string,
			expectedChallenge: string
		) {
			const actualChallenge = await generateChallenge(code_verifier);
			return actualChallenge === expectedChallenge;
		}
		const result = verifyChallenge(code_verifier, ctx.req.authorizationServerState.code_challenge);

		if (!result) {
			console.log("invalid code_verifier");
			ctx.res.status(400).send({ error: `invalid code_verifier` });
			return;
		}
	}

	private async tokenRequestHandleDpopHeader(ctx: { req: Request, res: Response }) {
		if (ctx.res.headersSent) {
			return;
		}

		if (ctx.req.body.grant_type != GrantType.AUTHORIZATION_CODE && ctx.req.body.grant_type != GrantType.REFRESH_TOKEN) {
			return; // this is not a job for this handler, let the other ones to decide on the request
		}

		const dpopJwt = ctx.req.headers['dpop'] as string | undefined;
		if (!dpopJwt) {
			console.log("DPoP header not found");
			ctx.res.status(400).send({ error: "DPoP header not found" });
			return;
		}
		const [header, payload] = dpopJwt.split('.').slice(0, 2).map((part) => JSON.parse(base64url.decode(part))) as Array<any>;
		const { typ, alg, jwk } = header;

		if (typ !== "dpop+jwt") {
			console.log("DPoP error: invalid typ value for dpop header");
			ctx.res.status(400).send({ error: "DPoP error: invalid typ value for dpop header" });
			return;
		}

		if (alg !== "ES256") {
			console.log("DPoP error: unsupported algorithm");
			ctx.res.status(400).send({ error: "DPoP error: unsupported algorithm" });
			return;
		}

		try {
			await jwtVerify(dpopJwt, await importJWK(jwk as JWK, 'ES256'));
		}
		catch (err) {
			console.error(err);
			console.log("DPoP error: invalid signature");
			ctx.res.status(400).send({ error: "DPoP error: invalid signature" });
			return;
		}

		ctx.req.authorizationServerState.dpop_jwk = JSON.stringify(jwk);

		const { htu, htm, jti } = payload;

		if (htm !== "POST") {
			console.log("DPoP error: invalid htm");
			ctx.res.status(400).send({ error: "DPoP error: invalid htm" });
			return;
		}


		if (htu !== `${config.url}/openid4vci/token`) {
			console.log("DPoP error: invalid htu");
			ctx.res.status(400).send({ error: "DPoP error: invalid htu" });
			return;
		}
		ctx.req.authorizationServerState.dpop_jti = jti;


	}

	private async generateTokenResponse(ctx: { req: Request, res: Response }) {
		ctx.req.authorizationServerState.access_token = crypto.randomBytes(16).toString('hex');
		ctx.req.authorizationServerState.token_type = "DPoP";
		ctx.req.authorizationServerState.access_token_expiration_timestamp = Math.floor(Date.now() / 1000) + access_token_expires_in;

		ctx.req.authorizationServerState.c_nonce = crypto.randomBytes(16).toString('hex');
		ctx.req.authorizationServerState.c_nonce_expiration_timestamp = Math.floor(Date.now() / 1000) + c_nonce_expires_in;

		/**
		 * No rotation in refresh token. A new refresh token will not be issued every time in case of refresh_token grant type
		 */
		if (!ctx.req.authorizationServerState.refresh_token) {
			ctx.req.authorizationServerState.refresh_token = crypto.randomBytes(16).toString('hex');
			ctx.req.authorizationServerState.refresh_token_expiration_timestamp = Math.floor(Date.now() / 1000) + refresh_token_expires_in;
		}

		return {
			token_type: ctx.req.authorizationServerState.token_type,
			access_token: ctx.req.authorizationServerState.access_token,
			expires_in: access_token_expires_in,
			c_nonce: ctx.req.authorizationServerState.c_nonce,
			c_nonce_expires_in: c_nonce_expires_in,
			refresh_token: ctx.req.authorizationServerState.refresh_token,
			auth_session: ctx.req.authorizationServerState.auth_session
		}
	}


	// @ts-ignore
	private async tokenRequestRefreshTokenGrantHandler(ctx: { req: Request, res: Response }): Promise<void> {
		if (ctx.res.headersSent) {
			return;
		}

		if (ctx.req.body.grant_type != GrantType.REFRESH_TOKEN) {
			return; // this is not a job for this handler, let the other ones to decide on the request
		}

		// get state by refresh token
		const state = await this.authorizationServerStateRepository.createQueryBuilder("state")
			.where("state.refresh_token = :refresh_token", { refresh_token: ctx.req.body.refresh_token })
			.getOne();

		if (!state || !state?.refresh_token || !state.refresh_token_expiration_timestamp || state.refresh_token_expiration_timestamp < Math.floor(Date.now() / 1000)) {
			const response = {
				"error": "invalid_grant",
				"error_description": "The refresh token is expired or invalid."
			};
			console.log(response);
			ctx.res.status(400).send(response);
			return;
		}

		ctx.req.authorizationServerState = state; // update state
	}

	async tokenRequestHandler(ctx: { req: Request, res: Response }): Promise<void> {
		await this.tokenRequestGrantTypeHandler(ctx);
		await this.tokenRequestAuthorizationCodeHandler(ctx);  // updates ctx.req.authorizationServerState based on received code in case of authorization_code grant type
		await this.tokenRequestRefreshTokenGrantHandler(ctx); // updates ctx.req.authorizationServerState based on received refresh_token in case of refresh_token grant type
		await this.tokenRequestHandleDpopHeader(ctx);
		await this.tokenRequestCodeVerifierHandler(ctx);
		// await this.tokenRequestPreAuthorizedCodeHandler(ctx);
		// await this.tokenRequestUserPinHandler(ctx); keep this commented to not require userpin

		if (ctx.res.headersSent) {
			return;
		}
		try {
			const response = await this.generateTokenResponse(ctx);
			await this.authorizationServerStateRepository.save(ctx.req.authorizationServerState);
			if (response) {
				ctx.res.setHeader("Cache-Control", "no-store");
				console.log("Token response = ", response)
				ctx.res.send(response);
			}
		}
		catch (err) {
			console.error("Couldn't generate access token. Detailed error:");
			console.error(err);
			ctx.res.status(400).send({ error: "Couldn't generate access token" });
			return;
		}
	}

	async credentialRequestHandler(ctx: { req: Request, res: Response }): Promise<void> {
		if (!ctx.req.headers.authorization) {
			const msg = "No authorization header was given";
			console.log(msg);
			ctx.res.status(401).send({ msg });
			return;
		}
		const [tokenType, access_token] = ctx.req.headers.authorization.split(' ');
		if (tokenType != 'DPoP') {
			const msg = "Expected DPoP access token";
			console.log(msg);
			ctx.res.status(401).send({ msg });
			return;
		}
		let state = await this.authorizationServerStateRepository.createQueryBuilder("state")
			.where("state.access_token = :access_token", { access_token: access_token })
			.getOne();
		if (!state) {
			const msg = "Invalid access_token";
			console.log(msg);
			ctx.res.status(401).send({ msg });
			return;
		}

		ctx.req.authorizationServerState = state;

		if (state?.access_token_expiration_timestamp as number < Math.floor(Date.now() / 1000)) {
			console.log("Expired access_token");
			ctx.res.status(400).send({ error: "Expired access_token" });
			return;
		}

		async function dpopVerification() {
			if (!state) {
				const msg = "CredentialRequest: Invalid access_token";
				console.log(msg);
				ctx.res.status(401).send({ error: "Invalid access_token" });
				return;
			}

			const dpopJwt = ctx.req.headers['dpop'] as string | undefined;
			if (!dpopJwt) {
				console.log("CredentialRequest: DPoP header not found");
				ctx.res.status(400).send({ error: "DPoP header not found" });
				return;
			}

			try {
				await jwtVerify(dpopJwt, await importJWK(JSON.parse(state.dpop_jwk as string) as JWK, 'ES256'));
			}
			catch (err) {
				console.log(err)
				console.log("CredentialRequest: Invalid access token");
				ctx.res.status(400).send({ error: "Invalid access token" });
				return;
			}



			const [_header, payload] = dpopJwt.split('.').slice(0, 2).map((part) => JSON.parse(base64url.decode(part))) as Array<any>;
			const { htu, htm, jti, ath } = payload;
			if (!jti || jti === state.dpop_jti) {
				console.log("CredentialRequest: Missing or re-used dpop jti");
				ctx.res.status(400).send({ error: "Missing or re-used dpop jti" });
				return;
			}

			if (!htu || htu !== `${config.url}/openid4vci/credential`) {
				console.log("CredentialRequest: Invalid htu");
				ctx.res.status(400).send({ error: "Invalid htu" });
				return;
			}

			async function calculateAth(accessToken: string) {
				// Encode the access token as a Uint8Array
				const encoder = new TextEncoder();
				const accessTokenBuffer = encoder.encode(accessToken);

				// Compute the SHA-256 hash of the access token
				const hashBuffer = await crypto.webcrypto.subtle.digest('SHA-256', accessTokenBuffer);

				// Convert ArrayBuffer to Base64URL string
				const base64Url = arrayBufferToBase64Url(hashBuffer);

				return base64Url;
			}



			if (!htm || htm !== `POST`) {
				console.log("CredentialRequest: Invalid htm");
				ctx.res.status(400).send({ error: "Invalid htm" });
				return;
			}

			if (!ath || ath !== await calculateAth(state.access_token as string)) {
				console.log("CredentialRequest: Invalid ath");
				ctx.res.status(400).send({ error: "Invalid ath" });
				return;
			}
		}

		await dpopVerification();

		if (ctx.res.headersSent) {
			return;
		}

		async function keyAttestationVerificaton() {
			// @ts-ignore
			const supportedBatchSize: number = config.issuanceFlow?.batchCredentialIssuance?.batchSize ?? 1;

			if (ctx.req.body?.proof?.proof_type && ctx.req.body?.proof?.proof_type === 'attestation' && ctx.req.body?.proof?.attestation && typeof ctx.req.body.proof.attestation === 'string') {
				const attestation = ctx.req.body.proof.attestation as string;
				const header = JSON.parse(base64url.decode(attestation.split('.')[0])) as Record<string, unknown>;
				if (header.x5c && header.alg && Array.isArray(header.x5c) && typeof header.alg === 'string') {
					const verificationResult = await verifyX5C(header.x5c as string[], [ ...config.trustedRootCertificates ]);
					console.log("Chain validation result = ", verificationResult)
					if (!verificationResult) {
						const r = { error: "Key attestation: Chain validation error" };
						console.log(r);
						return r;
					}
					try {
						const x509 = `-----BEGIN CERTIFICATE-----\n${(header.x5c as string[])[0]}\n-----END CERTIFICATE-----`
						const publicKey = await importX509(x509, header.alg);
						const { payload } = await jwtVerify(attestation, publicKey);
						if (!payload.attested_keys) {
							const r = { error: "Key attestation: 'attested_keys' claim is missing from key attestation JWT payload" };
							console.error(r);
							return r;
						}
						if (Array.isArray(payload.attested_keys) && payload.attested_keys.length > supportedBatchSize) {
							const r = { error: "Key attestation: 'attested_keys' length is bigger than the supported batch size" };
							console.error(r);
							return r;
						}
						return { attested_keys: payload.attested_keys as JWK[] };
					}
					catch(err) {
						const r = { error: "Key attestation: Signature validation failed" };
						console.error(r);
						console.error(err);
						return r;
					}
				}
			}
			const r = { error: "Key attestation: Nothing to verify the received key attestation" };
			console.error(r);
			return r;
		}

		async function proofJwtVerification() {
			// @ts-ignore
			const supportedBatchSize: number = config.issuanceFlow?.batchCredentialIssuance?.batchSize ?? 1;

			if (ctx.req.body?.proofs?.jwt && ctx.req.body?.proofs?.jwt instanceof Array && ctx.req.body?.proofs?.jwt.length > supportedBatchSize) {
				return { error: "Proof jwt: Exceeding supported batch size" };
			}

			const proofs: string[] = ctx.req.body.proofs ? ctx.req.body.proofs.jwt : [ctx.req.body.proof.jwt];
			const results = await Promise.all(proofs.map(async (proofJwt: string) => {
				const [header, payload] = proofJwt.split('.').slice(0, 2).map((part: string) => JSON.parse(base64url.decode(part))) as Array<any>;
				const { jwk, alg } = header;
				const { nonce } = payload;
				if (!alg || alg !== 'ES256') {
					return { error: "Proof jwt: Invalid alg" };
				}

				if (!nonce || nonce !== state?.c_nonce) {
					return { error: "Proof jwt: Invalid nonce" };
				}

				if (state?.c_nonce_expiration_timestamp as number < Math.floor(Date.now() / 1000)) {
					return { error: "Proof jwt: Expired c_nonce" };
				}

				try {
					await jwtVerify(proofJwt, await importJWK(jwk));
				}
				catch (err) {
					return { error: "Proof jwt: Invalid signature" }
				}
				return { jwk } as { jwk: JWK };
			}));

			return results;
		}

		const credentialConfigurationRegistryService = this.credentialConfigurationRegistryService;
	
		async function sendCredentialResponse(holderJwks: JWK[]) {
			const responses = (await Promise.all(holderJwks.map(async (jwk) => {
				return credentialConfigurationRegistryService.getCredentialResponse(ctx.req.authorizationServerState, ctx.req, jwk);
			}))).filter(r => r != null);
			const format = responses[0]?.format;

			console.log("Credential Responses to send = ", responses);
			if (holderJwks.length > 1) {
				ctx.res.send({
					credentials: responses.map((response: any) => response.credential),
					format: format,
				});
				return;
			}
			else {
				ctx.res.send({
					credential: responses.map((response: any) => response.credential)[0],
					format: format,
				});
				return;
			}
		}

		if (ctx.req.body.proof?.proof_type === 'attestation') {
			const keyAttestationVerificationResult = await keyAttestationVerificaton();
			console.log("Key attestation result = ", keyAttestationVerificationResult)
			if ('error' in keyAttestationVerificationResult) {
				ctx.res.status(400).send({ error: keyAttestationVerificationResult.error });
				return;	
			}
			await sendCredentialResponse([...keyAttestationVerificationResult.attested_keys]);
			return;
		}
		else {
			const results = await proofJwtVerification();
			if (!('error' in results) && results instanceof Array) {
				await sendCredentialResponse(results.map((r) => 'jwk' in r ? r.jwk : null).filter(r => r !== null) as JWK[]);
				return;
			}
		}

		console.log("Failed to generate credential response")
		ctx.res.status(400).send({ error: "Failed to generate credential response" });
	}

}