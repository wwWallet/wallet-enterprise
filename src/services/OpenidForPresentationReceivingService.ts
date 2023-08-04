import { inject, injectable } from "inversify";
import { Request , Response} from 'express'
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface, WalletKeystore } from "./interfaces";
import { authorizationRequestQueryParamsSchema } from "../types/oid4vci";
import { AuthorizationRequestQueryParamsSchemaType } from "../types/oid4vci";
import { TYPES } from "./types";
import { SignJWT, importJWK, jwtVerify } from "jose";
import { randomUUID } from "crypto";
import base64url from "base64url";
import { PresentationSubmission, getPublicKeyFromDid } from "@gunet/ssi-sdk";
import config from "../../config";
import 'reflect-metadata';
import { JSONPath } from "jsonpath-plus";
import { ParamsDictionary } from "express-serve-static-core";
import { ParsedQs } from "qs";


type VerifierState = {
	authorizationRequest: AuthorizationRequestQueryParamsSchemaType,
	userSessionID: string;
}

const verifierStates = new Map<string, VerifierState>();

const clientStates = new Map<string, string>(); // key: state given by the client, value: verifierStateId
const nonces = new Map<string, string>(); // key: nonce, value: verifierStateId

@injectable()
export class OpenidForPresentationsReceivingService implements OpenidForPresentationsReceivingInterface {


	constructor(
		@inject(TYPES.VerifierConfigurationServiceInterface) private configurationService: VerifierConfigurationInterface,
		@inject(TYPES.FilesystemKeystoreService) private walletKeystoreService: WalletKeystore,
	) {}

	
	metadataRequestHandler(_req: Request, _res: Response): Promise<void> {
		throw new Error("Method not implemented.");
	}



	async authorizationRequestHandler(req: Request, res: Response, userSessionIdToBindWith: string): Promise<void> {
		const { success } = authorizationRequestQueryParamsSchema.safeParse(req.query);
		if (!success) {
			res.status(400).send({ error: "Authorization request params are incorrect" });
			return;
		}
		const {
			state,
			redirect_uri,
			client_id,
			scope
		} = req.query as AuthorizationRequestQueryParamsSchemaType;
		
		const scopeList = scope.split(' ');


		const verifierStateId = randomUUID();
		const flowState: VerifierState = {
			authorizationRequest: req.query as AuthorizationRequestQueryParamsSchemaType,
			userSessionID: userSessionIdToBindWith,
		};
		const nonce = randomUUID();
		nonces.set(nonce, verifierStateId);
		console.log("NONCE1 = ", nonce)

		if (state) {
			clientStates.set(state, verifierStateId);
		}

		const responseTypeSetting = scopeList.includes("ver_test:vp_token") ? "vp_token" : "id_token";

		let payload = {
			client_id: this.configurationService.getConfiguration().client_id,
			response_type: responseTypeSetting,
			response_mode: "direct_post",
			redirect_uri: this.configurationService.getConfiguration().redirect_uri,
			scope: "openid",
			nonce: nonce,
			iss: this.configurationService.getConfiguration().client_id,
			aud: client_id,
		};
		if (state) {
			payload = { ...payload, state } as any;
		}

		// update payload according to response type setting
		switch (responseTypeSetting) {
		case "id_token":
			payload = await this.addIDtokenRequestSpecificAttributes(payload);
			break;
		case "vp_token":
			payload = await this.addVPtokenRequestSpecificAttributes(payload);
			break;
		}

		const requestJwt = new SignJWT(payload)
			.setExpirationTime('30s')

		const { jws } = await this.walletKeystoreService.signJwt(
			this.configurationService.getConfiguration().authorizationServerWalletIdentifier,
			requestJwt,
			"JWT");

		const requestJwtSigned = jws;
		
		const redirectParameters = {
			...payload,
			request: requestJwtSigned,
		};

		const searchParams = new URLSearchParams(redirectParameters);
		const redirectURL = new URL(redirect_uri + "?" + searchParams.toString());

		verifierStates.set(verifierStateId, { ...flowState, userSessionID: userSessionIdToBindWith })
		console.log("redirecting to = ", redirectURL)
		res.redirect(redirectURL.toString());
	}

	private async addIDtokenRequestSpecificAttributes(payload: any) {
		return payload;
	}

	private async addVPtokenRequestSpecificAttributes(payload: any) {
		payload = { ...payload, presentation_definition: this.configurationService.getPresentationDefinition() };
		return payload;
	}



	async responseHandler(req: Request, res: Response): Promise<{ verifierStateId: string, bindedUserSessionId: string }> {
		console.log("Body = ", req.body)
		const { id_token, vp_token, state, presentation_submission } = req.body;
		let verifierStateId = null;
		let verifierState = null;
		if (state) {
			verifierStateId = clientStates.get(state);
			if (verifierStateId)
				verifierState = verifierStates.get(verifierStateId)
		}
		if (id_token) {
			const header = JSON.parse(base64url.decode(id_token.split('.')[0])) as { kid: string, alg: string };
			const jwk = await getPublicKeyFromDid(header.kid.split('#')[0]);
			const pubKey = await importJWK(jwk, header.alg as string);

			console.log("ID token = ", id_token)
			try {
				const { payload } = await jwtVerify(id_token, pubKey, {
					// audience: this.configurationService.getConfiguration().baseUrl,
				});
				const { nonce } = payload;
				// load verifier state by nonce
				if (!verifierState) {
					let verifierStateIdByNonce = nonces.get(nonce as string);
					if (!verifierStateIdByNonce) {
						const msg = { error: "EXPIRED_NONCE", error_description: "This nonce does not exist or has expired" };
						console.error(msg);
						const searchParams = new URLSearchParams(msg);
						res.redirect(config.walletClientUrl + '?' + searchParams);
						throw new Error("OpenID4VP Authorization Response failed. " + msg);
					}
					verifierState = verifierStates.get(verifierStateIdByNonce);
				}
				
				const state = verifierState?.authorizationRequest.state;
				if (!verifierState) {
					const msg = { error: "ERROR_NONCE", error_description: "There is no verifier state with this 'nonce'" };
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					res.redirect(config.walletClientUrl + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}

				if (payload.sub !== verifierState?.authorizationRequest.client_id) {
					let msg = { error: "INVALID_SUB", error_description: "Subject of id_token should match authorizationRequest.client_id" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					res.redirect(verifierState?.authorizationRequest.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}

				if (payload.iss !== verifierState?.authorizationRequest.client_id) {
					let msg = { error: "INVALID_ISS", error_description: "Issuer of id_token should match authorizationRequest.client_id" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					res.redirect(verifierState?.authorizationRequest.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}
				

				if (!nonce || typeof nonce != 'string') {
					let msg = { error: "ERROR_NONCE", error_description: "'nonce' does not exist or is not of type 'string" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					res.redirect(verifierState?.authorizationRequest.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}
				return { verifierStateId: verifierStateId as string, bindedUserSessionId: verifierState.userSessionID };
			}
			catch(e) {
				throw new Error("OpenID4VP Authorization Response failed. " + JSON.stringify(e));
			}

		}
		else if (vp_token) {
			const header = JSON.parse(base64url.decode(vp_token.split('.')[0])) as { kid: string, alg: string };
			const jwk = await getPublicKeyFromDid(header.kid.split('#')[0]);
			const pubKey = await importJWK(jwk, header.alg as string);

			console.log("VP token = ", vp_token)
			try {
				const { payload } = await jwtVerify(vp_token, pubKey, {
					// audience: this.configurationService.getConfiguration().baseUrl,
				});
				const { nonce } = payload;
				// load verifier state by nonce
				if (!verifierState) {
					let verifierStateIdByNonce = nonces.get(nonce as string);
					if (!verifierStateIdByNonce) {
						const msg = { error: "EXPIRED_NONCE", error_description: "This nonce does not exist or has expired" };
						console.error(msg);
						const searchParams = new URLSearchParams(msg);
						res.redirect(config.walletClientUrl + '?' + searchParams);
						throw new Error("OpenID4VP Authorization Response failed. " + msg);
					}
					verifierState = verifierStates.get(verifierStateIdByNonce);
				}

				if (!verifierState) {
					const msg = { error: "ERROR_NONCE", error_description: "There is no verifier state with this 'nonce'" };
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					res.redirect(config.walletClientUrl + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}

				if (payload.sub !== verifierState?.authorizationRequest.client_id) {
					let msg = { error: "INVALID_SUB", error_description: "Subject of id_token should match authorizationRequest.client_id" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					res.redirect(verifierState?.authorizationRequest.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed." + msg);
				}

				if (payload.iss !== verifierState?.authorizationRequest.client_id) {
					let msg = { error: "INVALID_ISS", error_description: "Issuer of id_token should match authorizationRequest.client_id" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					res.redirect(verifierState?.authorizationRequest.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}
				

				if (!nonce || typeof nonce != 'string') {
					let msg = { error: "ERROR_NONCE", error_description: "'nonce' does not exist or is not of type 'string" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					res.redirect(verifierState?.authorizationRequest.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}
				// perform verification of vp_token
				presentation_submission
				let msg = { error: "access_denied", error_description: "invalid" };
				if (state) {
					msg = { ...msg, state } as any;
				}
				const { error, error_description } = await this.validateVpToken(vp_token, presentation_submission);
				if (error && error_description) {
					msg = { ...msg, error: error.message, error_description: error_description?.message };
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					res.redirect(verifierState?.authorizationRequest.redirect_uri + '?' + searchParams);
					throw new Error(error.message + "\n" + error_description?.message);
				}
				console.error(msg);
				const searchParams = new URLSearchParams(msg);
				res.redirect(verifierState?.authorizationRequest.redirect_uri + '?' + searchParams);
				return { verifierStateId: verifierStateId as string, bindedUserSessionId: verifierState.userSessionID };
			}
			catch(e) {
				throw new Error("OpenID4VP Authorization Response failed. " + JSON.stringify(e));
			}
		}
		throw new Error("OpenID4VP Authorization Response failed. Path not implemented");
	}

	private async validateVpToken(vp_token: string, presentation_submission: PresentationSubmission): Promise<{ error?: Error, error_description?: Error}> {
		const payload = JSON.parse(base64url.decode(vp_token.split('.')[1])) as { vp: { verifiableCredential: string[] } };
		for (const desc of presentation_submission.descriptor_map) {
			const path = desc.path_nested?.path as string;
			const vcjwt = JSONPath({ json: payload.vp, path: path });
			if (await this.isExpired(vcjwt)) {
				console.error({ error: new Error("access_denied"), error_description: new Error(`${desc.id} is expired`) })
				return { error: new Error("access_denied"), error_description: new Error(`${desc.id} is expired`) }
			}
			if (await this.isNotValidYet(vcjwt)) {
				console.error({ error: new Error("access_denied"), error_description: new Error(`${desc.id} is expired`) })
				return { error: new Error("access_denied"), error_description: new Error(`${desc.id} is not valid yet`) }

			}
			if (await this.isRevoked(vcjwt)) {
				console.error({ error: new Error("access_denied"), error_description: new Error(`${desc.id} is expired`) })
				return { error: new Error("access_denied"), error_description: new Error(`${desc.id} is revoked`) }
			}
		}
		return {};
	}

	private async isExpired(vcjwt: string): Promise<boolean> {
		const payload = JSON.parse(base64url.decode(vcjwt.split('.')[1])) as { exp: number };
		return payload.exp < Date.now();
	}

	private async isNotValidYet(vcjwt: string): Promise<boolean> {
		const payload = JSON.parse(base64url.decode(vcjwt.split('.')[1])) as { nbf: number };
		return payload.nbf > Date.now();
	}

	private async isRevoked(_vcjwt: string): Promise<boolean> {
		return true;
	}


	async sendAuthorizationResponse(_req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>, res: Response<any, Record<string, any>>, verifierStateId: string): Promise<void> {
		const verifierState = verifierStates.get(verifierStateId);
		const state = verifierState?.authorizationRequest.state;
		const code = randomUUID();
		let msg: any = { code };
		if (state)
			msg = { ...msg, state };

		const searchParams = new URLSearchParams(msg);
		res.redirect(verifierState?.authorizationRequest.redirect_uri + '?' + searchParams);
	}
}