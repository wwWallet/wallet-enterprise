import { inject, injectable } from "inversify";
import { Request , Response} from 'express'
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "./interfaces";
import { VerifiableCredentialFormat } from "../types/oid4vci";
import { AuthorizationRequestQueryParamsSchemaType } from "../types/oid4vci";
import { TYPES } from "./types";
import { importJWK, jwtVerify } from "jose";
import { KeyLike, createHash, randomUUID, verify } from "crypto";
import base64url from "base64url";
import { PresentationDefinitionType, PresentationSubmission } from "@wwwallet/ssi-sdk";
import 'reflect-metadata';
import { JSONPath } from "jsonpath-plus";
import { Repository } from "typeorm";
import { ClaimRecord, PresentationClaims, VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
import AppDataSource from "../AppDataSource";
import { verificationCallback } from "../configuration/verificationCallback";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
import config from "../../config";
import { DidKeyResolverService } from "./DidKeyResolverService";
import { HasherAlgorithm, HasherAndAlgorithm, SdJwt, SignatureAndEncryptionAlgorithm, Verifier } from "@sd-jwt/core";

const hasherAndAlgorithm: HasherAndAlgorithm = {
	hasher: (input: string) => createHash('sha256').update(input).digest(),
	algorithm: HasherAlgorithm.Sha256
}

type VerifierState = {
	callbackEndpoint?: string;
	authorizationRequest?: AuthorizationRequestQueryParamsSchemaType;
	issuanceSessionID?: number;
	presentation_definition?: PresentationDefinitionType;
}

const verifierStates = new Map<string, VerifierState>();

const CLOCK_TOLERANCE = '15 minutes';

const clientStates = new Map<string, string>(); // key: state given by the client, value: verifierStateId
const nonces = new Map<string, string>(); // key: nonce, value: verifierStateId

@injectable()
export class OpenidForPresentationsReceivingService implements OpenidForPresentationsReceivingInterface {
	private verifiablePresentationRepository: Repository<VerifiablePresentationEntity> = AppDataSource.getRepository(VerifiablePresentationEntity);
	// private authorizationServerStateRepository: Repository<AuthorizationServerState> = AppDataSource.getRepository(AuthorizationServerState);

	constructor(
		@inject(TYPES.DidKeyResolverService) private didKeyResolverService: DidKeyResolverService,
		@inject(TYPES.VerifierConfigurationServiceInterface) private configurationService: VerifierConfigurationInterface,
	) {}


	
	metadataRequestHandler(_ctx: { req: Request, res: Response }): Promise<void> {
		throw new Error("Method not implemented.");
	}


	// @ts-ignore
	private async addIDtokenRequestSpecificAttributes(payload: any) {
		return payload;
	}

	private async addVPtokenRequestSpecificAttributes(verifierStateId: string, payload: any, presentation_definition_id: string) {
		const found = this.configurationService.getPresentationDefinitions().filter(pd => pd.id == presentation_definition_id);
		console.log("Found = ", found[0])
		if (found.length > 0) {
			const presentationDefinition = found[0];
			const verifierState = verifierStates.get(verifierStateId);
			if (verifierState) {
				verifierStates.set(verifierStateId, { ...verifierState, presentation_definition: presentationDefinition })
				payload = { ...payload, presentation_definition_uri: config.url + '/verification/definition?state=' + payload.state };
				return payload;
			}
		}
	}
	
	public async getPresentationDefinitionHandler(ctx: { req: Request, res: Response }): Promise<void> {
		const state = ctx.req.query.state as string;
		if (state) {
			const verifierState = verifierStates.get(state);
			if (verifierState?.presentation_definition) {
				ctx.res.send(verifierState?.presentation_definition);
				return;
			}
		}
		ctx.res.status(404).send({ msg: "not found" });
	}

	
	async generateAuthorizationRequestURL(ctx: { req: Request, res: Response }, presentation_definition_id: string, callbackEndpoint?: string): Promise<{ url: URL; stateId: string }> {
		const nonce = randomUUID();
		const stateId = randomUUID();
		nonces.set(nonce, stateId);
		let payload = {
			client_id: this.configurationService.getConfiguration().client_id,
			client_id_scheme: "redirect_uri",
			response_type: "vp_token",
			response_mode: "direct_post",
			response_uri: this.configurationService.getConfiguration().redirect_uri,
			scope: "openid",
			nonce: nonce,
			state: stateId,
		};

		// try to get the redirect uri from the authorization server state in case this is a Dynamic User Authentication during OpenID4VCI authorization code flow
		const redirectUri = ctx.req?.authorizationServerState?.redirect_uri ?? "openid://cb";

		verifierStates.set(stateId, { callbackEndpoint });
		payload = await this.addVPtokenRequestSpecificAttributes(stateId, payload, presentation_definition_id);
		console.log("Payload = ", payload)
		// const requestJwt = new SignJWT(payload)
		// 	.setExpirationTime('30s');

		// const { jws } = await this.walletKeystoreService.signJwt(
		// 	this.configurationService.getConfiguration().authorizationServerWalletIdentifier,
		// 	requestJwt,
		// 	"JWT"
		// );

		// const requestJwtSigned = jws;
		const redirectParameters = {
			...payload,
			// request: requestJwtSigned,
		};

		const searchParams = new URLSearchParams(redirectParameters);
		const authorizationRequestURL = new URL(redirectUri + "?" + searchParams.toString()); // must be openid://cb
		return { url: authorizationRequestURL, stateId };
	}


	async responseHandler(ctx: { req: Request, res: Response }): Promise<{ verifierStateId: string, bindedUserSessionId?: number, vp_token?: string }> {
		console.log("Body = ", ctx.req.body)
		const { id_token, vp_token, state, presentation_submission } = ctx.req.body;
		console.log("Id token = ", id_token)
		// let presentationSubmissionObject: PresentationSubmission | null = qs.parse(decodeURI(presentation_submission)) as any;
		let presentationSubmissionObject: PresentationSubmission | null = presentation_submission ? JSON.parse(decodeURI(presentation_submission)) as any : null;

		console.log("Presentation submission object = ", presentationSubmissionObject)
		// if (presentation_submission) {
		// 	presentationSubmissionObject
		// }

		let verifierStateId = null;
		let verifierState = null;
		if (state) {
			verifierStateId = clientStates.get(state);
			if (verifierStateId)
				verifierState = verifierStates.get(verifierStateId)
		}
		if (id_token) {
			const header = JSON.parse(base64url.decode(id_token.split('.')[0])) as { kid: string, alg: string };
			const jwk = await this.didKeyResolverService.getPublicKeyJwk(header.kid.split('#')[0]);
			const pubKey = await importJWK(jwk, header.alg as string);

			try {
				const { payload } = await jwtVerify(id_token, pubKey, {
					clockTolerance: CLOCK_TOLERANCE
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
						ctx.res.redirect("/error" + '?' + searchParams);
						throw new Error("OpenID4VP Authorization Response failed. " + msg);
					}
					verifierState = verifierStates.get(verifierStateIdByNonce);
				}
				
				const state = verifierState?.authorizationRequest?.state;
				if (!verifierState) {
					const msg = { error: "ERROR_NONCE", error_description: "There is no verifier state with this 'nonce'" };
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect("/error" + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}

				if (payload.sub !== verifierState?.authorizationRequest?.client_id) {
					let msg = { error: "INVALID_SUB", error_description: "Subject of id_token should match authorizationRequest.client_id" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}

				if (payload.iss !== verifierState?.authorizationRequest?.client_id) {
					let msg = { error: "INVALID_ISS", error_description: "Issuer of id_token should match authorizationRequest.client_id" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}
				

				if (!nonce || typeof nonce != 'string') {
					let msg = { error: "ERROR_NONCE", error_description: "'nonce' does not exist or is not of type 'string" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}
				return { verifierStateId: verifierStateId as string, bindedUserSessionId: verifierState.issuanceSessionID };
			}
			catch(e) {
				throw new Error("OpenID4VP Authorization Response failed. " + JSON.stringify(e));
			}

		}
		else if (vp_token) {
			const header = JSON.parse(base64url.decode(vp_token.split('.')[0])) as { kid: string, alg: string };
			const jwk = await this.didKeyResolverService.getPublicKeyJwk(header.kid.split('#')[0]);
			const pubKey = await importJWK(jwk, header.alg as string);

			try {
				const { payload } = await jwtVerify(vp_token, pubKey, {
					clockTolerance: CLOCK_TOLERANCE
					// audience: this.configurationService.getConfiguration().baseUrl,
				});
				const { nonce } = payload;
				// load verifier state by nonce
				if (!verifierState) {
					let verifierStateIdByNonce = nonces.get(nonce as string);
					verifierStateId = verifierStateIdByNonce;
					if (!verifierStateIdByNonce) {
						const msg = { error: "EXPIRED_NONCE", error_description: "This nonce does not exist or has expired" };
						console.error(msg);
						const searchParams = new URLSearchParams(msg);
						ctx.res.redirect("/error" + '?' + searchParams);
						throw new Error("OpenID4VP Authorization Response failed. " + msg);
					}
					verifierState = verifierStates.get(verifierStateIdByNonce);
				}

				if (!verifierState) {
					const msg = { error: "ERROR_NONCE", error_description: "There is no verifier state with this 'nonce'" };
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect("/error" + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}

				// if (payload.sub !== verifierState?.authorizationRequest?.client_id) {
				// 	let msg = { error: "INVALID_SUB", error_description: "Subject of vp_token should match authorizationRequest.client_id" };
				// 	if (state) {
				// 		msg = { ...msg, state } as any;
				// 	}
				// 	console.error(msg);
				// 	const searchParams = new URLSearchParams(msg);
				// 	res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
				// 	throw new Error("OpenID4VP Authorization Response failed." + msg);
				// }

				// if (payload.iss !== verifierState?.authorizationRequest?.client_id) {
				// 	let msg = { error: "INVALID_ISS", error_description: "Issuer of vp_token should match authorizationRequest.client_id" };
				// 	if (state) {
				// 		msg = { ...msg, state } as any;
				// 	}
				// 	console.error(msg);
				// 	const searchParams = new URLSearchParams(msg);
				// 	res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
				// 	throw new Error("OpenID4VP Authorization Response failed. " + msg);
				// }
				

				if (!nonce || typeof nonce != 'string') {
					let msg = { error: "ERROR_NONCE", error_description: "'nonce' does not exist or is not of type 'string" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}
				// perform verification of vp_token
				let msg = {};
				if (state) {
					msg = { ...msg, state } as any;
				}
				const { presentationClaims, error, error_description } = await this.validateVpToken(vp_token, presentationSubmissionObject as PresentationSubmission);
				if (error && error_description) {
					msg = { ...msg, error: error.message, error_description: error_description?.message };
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
					throw new Error(error.message + "\n" + error_description?.message);
				}

				// store presentation
				const newVerifiablePresentation = new VerifiablePresentationEntity()
				newVerifiablePresentation.presentation_definition_id = presentation_submission.definition_id;
				newVerifiablePresentation.claims = presentationClaims ?? null;
				newVerifiablePresentation.status = true;
				newVerifiablePresentation.raw_presentation = vp_token;
				newVerifiablePresentation.presentation_submission = presentationSubmissionObject;
				newVerifiablePresentation.date = new Date();
				newVerifiablePresentation.state = verifierStateId as string;

				this.verifiablePresentationRepository.save(newVerifiablePresentation);

				console.error(msg);
				//@ts-ignore
				const searchParams = new URLSearchParams(msg);

				// if not in issuance flow, then redirect to complete the verification flow
				if (!verifierState.issuanceSessionID) {
					// ctx.res.send("OK")
					ctx.res.redirect(verifierState.callbackEndpoint + '?' + searchParams);
				}

				if (verifierState.issuanceSessionID) {
					const authorizationServerState = await AppDataSource.getRepository(AuthorizationServerState)
						.createQueryBuilder('state')
						.where("state.id = :id", { id: verifierState.issuanceSessionID })
						.getOne();
					if (authorizationServerState)
						await verificationCallback(authorizationServerState, payload.vp)
				}
				console.log("binding issuanc sesssion id = ", verifierState.issuanceSessionID)
				return { verifierStateId: verifierStateId as string, bindedUserSessionId: verifierState.issuanceSessionID };
			}
			catch(e) {
				console.error(e)
				throw new Error("OpenID4VP Authorization Response failed. " + JSON.stringify(e));
			}
		}
		throw new Error("OpenID4VP Authorization Response failed. Path not implemented");
	}

	private async validateVpToken(vp_token: string, presentation_submission: PresentationSubmission): Promise<{ presentationClaims?: PresentationClaims, error?: Error, error_description?: Error}> {
		let presentationClaims: PresentationClaims = {};
		const payload = JSON.parse(base64url.decode(vp_token.split('.')[1])) as { nonce: string, vp: { verifiableCredential: string[] } };

		const verifierStateId = nonces.get(payload.nonce);
		if (!verifierStateId) {
			return { error: new Error("WRONG_NONCE"), error_description: new Error("Verifier state was not found based on the nonce of the vp token")}
		}
		const verifierState = verifierStates.get(verifierStateId);
		if (!verifierState) {
			return { error: new Error("STATE_NOT_FOUND"), error_description: new Error("Verifier could not be received") };
		}
		if (verifierState.presentation_definition?.input_descriptors.length != presentation_submission.descriptor_map.length) {
			return { error: new Error("NOT_ENOUGH_CREDENTIALS") , error_description: new Error("Holder did not send all the requested credentials") };
		}


		for (const desc of presentation_submission.descriptor_map) {
			if (!presentationClaims[desc.id]) {
				presentationClaims[desc.id] = [];
			}
			const path = desc?.path as string;
			let vcjwt = JSONPath({ json: payload.vp, path: path })[0];
			if (vcjwt.length == 0) {
				return { error: new Error("VC_NOT_FOUND"), error_description: new Error(`Path on descriptor ${desc.id} not matching to a credential`)};
			}
			const input_descriptor = verifierState.presentation_definition.input_descriptors.filter((input_desc) => input_desc.id == desc.id)[0];
			if (!input_descriptor) {
				return { error: new Error("Input descriptor not found") };
			}

			if (desc.format == VerifiableCredentialFormat.VC_SD_JWT) {
				const requiredClaimNames = input_descriptor.constraints.fields.map((field) => {
					const fieldPath = field.path[0];
					const splittedPath = fieldPath.split('.');
					return splittedPath[splittedPath.length - 1]; // return last part of the path
				});

				const sdJwt = SdJwt.fromCompact(vcjwt).withHasher(hasherAndAlgorithm);
	
				const vcPayload = (JSON.parse(base64url.decode(vcjwt.split('.')[1])) as any).vc;
				const issuerDID = vcPayload.issuer;

				const issuerPublicKeyJwk = await this.didKeyResolverService.getPublicKeyJwk(issuerDID);
				const alg = (JSON.parse(base64url.decode(vcjwt.split('.')[0])) as any).alg;
				const issuerPublicKey = await importJWK(issuerPublicKeyJwk, alg);
				const verifyCb: Verifier = ({ header, message, signature }) => {
					if (header.alg !== SignatureAndEncryptionAlgorithm.ES256) {
							throw new Error('only ES256 is supported')
					}
					return verify(null, Buffer.from(message), issuerPublicKey as KeyLike, signature)
				}
	
				const verificationResult = await sdJwt.verify(verifyCb, requiredClaimNames);
				const prettyClaims = await sdJwt.getPrettyClaims();

				input_descriptor.constraints.fields.map((field) => {
					if (!presentationClaims[desc.id]) {
						presentationClaims[desc.id] = []; // initialize
					}
					const fieldPath = field.path[0]; // get first path
					const value = String(JSONPath({ path: fieldPath, json: prettyClaims.vc as any })[0]);
					const splittedPath = fieldPath.split('.');
					const claimName = splittedPath[splittedPath.length - 1];
					presentationClaims[desc.id].push({ name: claimName, value: value } as ClaimRecord);
				});
				console.log("Verification result = ", verificationResult)
				if (!verificationResult.isValid) {
					return { error: new Error("SD_JWT_VERIFICATION_FAILURE"), error_description: new Error(`Verification result ${JSON.stringify(verificationResult)}`) };
				}
			}
			else if (desc.format == VerifiableCredentialFormat.JWT_VC) {
				const vcPayload = JSON.parse(base64url.decode(vcjwt.split('.')[1])) as any;
				input_descriptor.constraints.fields.map((field) => {
					if (!presentationClaims[desc.id]) {
						presentationClaims[desc.id] = []; // initialize
					}
					const fieldPath = field.path[0]; // get first path
					const value = String(JSONPath({ path: fieldPath, json: vcPayload.vc })[0]);
					const splittedPath = fieldPath.split('.');
					const claimName = splittedPath[splittedPath.length - 1];
					presentationClaims[desc.id].push({ name: claimName, value: value } as ClaimRecord);
				});
			}
		}
		return { presentationClaims };
	}

	//@ts-ignore
	private async isExpired(vcjwt: string): Promise<boolean> {
		const payload = JSON.parse(base64url.decode(vcjwt.split('.')[1])) as { exp: number };
		return payload.exp ? payload.exp < Math.floor(Date.now() / 1000) : false;
	}
	
	//@ts-ignore
	// private async isNotValidYet(vcjwt: string): Promise<boolean> {
	// 	const payload = JSON.parse(base64url.decode(vcjwt.split('.')[1])) as { nbf: number };
	// 	return payload.nbf ? payload.nbf > Math.floor(Date.now() / 1000) : false;
	// }

	//@ts-ignore
	private async isRevoked(_vcjwt: string): Promise<boolean> {
		return false;
	}




	async sendAuthorizationResponse(ctx: { req: Request, res: Response }, verifierStateId: string): Promise<void> {
		const verifierState = verifierStates.get(verifierStateId);
		const state = verifierState?.authorizationRequest?.state;
		const code = randomUUID();
		let msg: any = { code };
		if (state)
			msg = { ...msg, state };

		const searchParams = new URLSearchParams(msg);
		ctx.res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
	}


	public async getPresentationByState(state: string): Promise<{ status: boolean, presentationClaims?: PresentationClaims }> {
		const vp = await this.verifiablePresentationRepository.createQueryBuilder('vp')
			.where("state = :state", { state: state })
			.getOne();
	
		if (!vp?.raw_presentation || !vp.claims)
			return { status: false };

		if (vp) 
			return { status: true, presentationClaims: vp.claims };
		else
			return { status: false };
	}
}