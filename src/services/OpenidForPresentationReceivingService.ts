import { inject, injectable } from "inversify";
import { Request, Response } from 'express'
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "./interfaces";
import { VerifiableCredentialFormat } from "../types/oid4vci";
import { TYPES } from "./types";
import { compactDecrypt, exportJWK, generateKeyPair, importJWK, importPKCS8, jwtVerify, SignJWT } from "jose";
import { createHash, randomUUID } from "crypto";
import base64url from "base64url";
import 'reflect-metadata';
import { JSONPath } from "jsonpath-plus";
import { Repository } from "typeorm";
import AppDataSource from "../AppDataSource";
import { config } from "../../config";
import { HasherAlgorithm, HasherAndAlgorithm, SdJwt, SignatureAndEncryptionAlgorithm, Verifier } from "@sd-jwt/core";
import fs from 'fs';
import path from "path";
import { ClaimRecord, PresentationClaims, RelyingPartyState } from "../entities/RelyingPartyState.entity";
import { generateRandomIdentifier } from "../lib/generateRandomIdentifier";
import * as z from 'zod';
import { verifyKbJwt } from "../util/verifyKbJwt";

const privateKeyPem = fs.readFileSync(path.join(__dirname, "../../../keys/pem.server.key"), 'utf-8').toString();
const x5c = JSON.parse(fs.readFileSync(path.join(__dirname, "../../../keys/x5c.server.json")).toString()) as Array<string>;

enum ResponseMode {
	DIRECT_POST = 'direct_post',
	DIRECT_POST_JWT = 'direct_post.jwt'
}

const ResponseModeSchema = z.nativeEnum(ResponseMode);

// @ts-ignore
const response_mode: ResponseMode = config?.presentationFlow?.response_mode ? ResponseModeSchema.parse(config?.presentationFlow?.response_mode) : ResponseMode.DIRECT_POST_JWT;

const hasherAndAlgorithm: HasherAndAlgorithm = {
	hasher: (input: string) => createHash('sha256').update(input).digest(),
	algorithm: HasherAlgorithm.Sha256
}

function uint8ArrayToBase64Url(array: any) {
	// Convert the Uint8Array to a binary string
	let binaryString = '';
	array.forEach((byte: any) => {
		binaryString += String.fromCharCode(byte);
	});

	// Convert the binary string to a Base64 string
	let base64String = btoa(binaryString);

	// Convert the Base64 string to Base64URL format
	let base64UrlString = base64String
		.replace(/\+/g, '-') // Replace + with -
		.replace(/\//g, '_') // Replace / with _
		.replace(/=+$/, ''); // Remove trailing '='

	return base64UrlString;
}

@injectable()
export class OpenidForPresentationsReceivingService implements OpenidForPresentationsReceivingInterface {
	private rpStateRepository: Repository<RelyingPartyState> = AppDataSource.getRepository(RelyingPartyState);

	constructor(
		@inject(TYPES.VerifierConfigurationServiceInterface) private configurationService: VerifierConfigurationInterface,
	) { }

	public async getSignedRequestObject(ctx: { req: Request, res: Response }): Promise<any> {
		if (!ctx.req.query['id'] || typeof ctx.req.query['id'] != 'string') {
			return ctx.res.status(500).send({ error: "id does not exist on query params" });
		}
		const rpState = await this.rpStateRepository.createQueryBuilder()
			.where("state = :state", { state: ctx.req.query['id'] })
			.getOne();

		if (!rpState) {
			return ctx.res.status(500).send({ error: "rpState state could not be fetched with this id" });
		}
		return ctx.res.send(rpState.signed_request.toString());
	}

	async generateAuthorizationRequestURL(ctx: { req: Request, res: Response }, presentationDefinition: any, sessionId: string, callbackEndpoint?: string): Promise<{ url: URL; stateId: string }> {
		// create cookie and add it to response

		console.log("Presentation Request: Session id used for authz req ", sessionId);

		const nonce = randomUUID();
		const state = randomUUID();

		const responseUri = this.configurationService.getConfiguration().redirect_uri;
		const client_id = new URL(responseUri).hostname

		const [rsaImportedPrivateKey, rpEphemeralKeypair] = await Promise.all([
			importPKCS8(privateKeyPem, 'RS256'),
			generateKeyPair('ECDH-ES')
		]);
		const [exportedEphPub, exportedEphPriv] = await Promise.all([
			exportJWK(rpEphemeralKeypair.publicKey),
			exportJWK(rpEphemeralKeypair.privateKey)
		]);

		exportedEphPub.kid = generateRandomIdentifier(8);
		exportedEphPriv.kid = exportedEphPub.kid;
		exportedEphPub.use = 'enc';

		const signedRequestObject = await new SignJWT({
			response_uri: responseUri,
			aud: "https://self-issued.me/v2",
			iss: new URL(responseUri).hostname,
			client_id_scheme: "x509_san_dns",
			client_id: client_id,
			response_type: "vp_token",
			response_mode: response_mode,
			state: state,
			nonce: nonce,
			presentation_definition: presentationDefinition,
			client_metadata: {
				"jwks": {
					"keys": [
						exportedEphPub
					]
				},
				"authorization_encrypted_response_alg": "ECDH-ES",
				"authorization_encrypted_response_enc": "A256GCM",
				"vp_formats": {
					"vc+sd-jwt": {
						"sd-jwt_alg_values": [
							"ES256",
						],
						"kb-jwt_alg_values": [
							"ES256",
						]
					}
				}
			},
		})
			.setIssuedAt()
			.setProtectedHeader({
				alg: 'RS256',
				x5c: x5c,
			})
			.sign(rsaImportedPrivateKey);
		// try to get the redirect uri from the authorization server state in case this is a Dynamic User Authentication during OpenID4VCI authorization code flow
		const redirectUri = ctx.req?.authorizationServerState?.redirect_uri ?? "openid4vp://cb";

		// verifierStates.set(state, { ephemeralKeyPair: rpEphemeralKeypair, callbackEndpoint, nonce, response_uri: responseUri, client_id: client_id, signedRequestObject, presentation_definition: presentationDefinition });


		const newRpState = new RelyingPartyState();
		newRpState.presentation_definition = presentationDefinition;
		newRpState.presentation_definition_id = presentationDefinition.id;

		newRpState.date_created = new Date();
		newRpState.nonce = nonce;
		newRpState.state = state;
		newRpState.rp_eph_pub = exportedEphPub;
		newRpState.rp_eph_priv = exportedEphPriv;
		newRpState.rp_eph_kid = exportedEphPub.kid;
		newRpState.audience = client_id;

		newRpState.session_id = sessionId;
		newRpState.signed_request = signedRequestObject;

		if (callbackEndpoint) {
			newRpState.callback_endpoint = callbackEndpoint;
		}


		await this.rpStateRepository.save(newRpState);

		const requestUri = config.url + "/verification/request-object?id=" + state;

		const redirectParameters = {
			client_id: client_id,
			request_uri: requestUri
		};

		const searchParams = new URLSearchParams(redirectParameters);
		const authorizationRequestURL = new URL(redirectUri + "?" + searchParams.toString()); // must be openid4vp://cb

		console.log("AUTHZ REQ = ", authorizationRequestURL);
		return { url: authorizationRequestURL, stateId: state };
	}


	private async handlePresentationDuringIssuance(ctx: { req: Request, res: Response }, rpState: RelyingPartyState) {
		rpState.presentation_during_issuance_session = base64url.encode(randomUUID());
		await this.rpStateRepository.save(rpState);
		ctx.res.send({ presentation_during_issuance_session: rpState.presentation_during_issuance_session });
	}

	async responseHandler(ctx: { req: Request, res: Response }): Promise<void> {
		// let presentationSubmissionObject: PresentationSubmission | null = qs.parse(decodeURI(presentation_submission)) as any;

		let vp_token = ctx.req.body?.vp_token;
		let state = ctx.req.body?.state;
		let presentation_submission = ctx.req.body.presentation_submission ? JSON.parse(decodeURI(ctx.req.body.presentation_submission)) as any : null;


		if (ctx.req.body.response) { // E2EE - JARM
			const { kid } = JSON.parse(base64url.decode(ctx.req.body.response.split('.')[0])) as { kid: string | undefined };
			if (!kid) {
				throw new Error("Couldnt extract kid");
			}
			// get rpstate only to get the private key to decrypt the response
			let rpState = await this.rpStateRepository.createQueryBuilder()
				.where("rp_eph_kid = :rp_eph_kid", { rp_eph_kid: kid })
				.getOne();
			if (!rpState) {
				throw new Error();
			}
			const rp_eph_priv = await importJWK(rpState.rp_eph_priv, 'ECDH-ES');
			const { plaintext } = await compactDecrypt(ctx.req.body.response, rp_eph_priv);
			const payload = JSON.parse(new TextDecoder().decode(plaintext)) as { state: string | undefined, vp_token: string | undefined, presentation_submission: any };
			if (!payload?.state) {
				throw new Error("Missing state");
			}

			// get rpState using the state value
			rpState = await this.rpStateRepository.createQueryBuilder()
				.where("state = :state", { state: payload.state })
				.getOne();

			if (!rpState) {
				throw new Error("Couldn't get rp state with state");
			}

			if (!payload.vp_token) {
				throw new Error("Encrypted Response: vp_token is missing");
			}

			if (!payload.presentation_submission) {
				throw new Error("Encrypted Response: presentation_submission is missing");
			}
			rpState.response_code = base64url.encode(randomUUID());
			rpState.encrypted_response = ctx.req.body.response;
			rpState.presentation_submission = payload.presentation_submission;
			console.log("Encoding....")
			rpState.vp_token = base64url.encode(JSON.stringify(payload.vp_token));
			rpState.date_created = new Date();
			console.log("Stored rp state = ", rpState)
			if (rpState.session_id.startsWith("auth_session:")) { // is presentation during issuance
				await this.handlePresentationDuringIssuance(ctx, rpState);
				return;
			}
			await this.rpStateRepository.save(rpState);

			if (!rpState.is_cross_device) {
				ctx.res.send({ redirect_uri: rpState.callback_endpoint + '#response_code=' + rpState.response_code })
				return;
			}
			// in cross-device scenario just return an empty response
			ctx.res.send();
			return;
		}

		if (!state) {
			console.log("Missing state param");
			ctx.res.status(401).send({ error: "Missing state param" });
			return;
		}

		if (!vp_token) {
			console.log("Missing state param")
			ctx.res.status(401).send({ error: "Missing state param" });
			return;
		}

		// get rpState using the state value
		const rpState = await this.rpStateRepository.createQueryBuilder()
			.where("state = :state", { state: state })
			.getOne();

		if (!rpState) {
			throw new Error("Couldn't get rp state with state");
		}
		rpState.response_code = base64url.encode(randomUUID());
		rpState.presentation_submission = presentation_submission;
		rpState.vp_token = base64url.encode(JSON.stringify(vp_token));
		rpState.date_created = new Date();

		console.log("Session id = ", rpState.session_id)
		if (rpState.session_id.startsWith("auth_session:")) { // is presentation during issuance
			await this.handlePresentationDuringIssuance(ctx, rpState);
			return;
		}
		await this.rpStateRepository.save(rpState);
		ctx.res.send({ redirect_uri: rpState.callback_endpoint + '#response_code=' + rpState.response_code })
		return;
	}

	private async validateVpToken(vp_token_list: string[] | string, presentation_submission: any, rpState: RelyingPartyState): Promise<{ presentationClaims?: PresentationClaims, error?: Error }> {
		let presentationClaims: PresentationClaims = {};

		for (const desc of presentation_submission.descriptor_map) {
			if (!presentationClaims[desc.id]) {
				presentationClaims[desc.id] = [];
			}

			const path = desc.path as string;
			const jsonPathResult = JSONPath({ json: vp_token_list, path: path });
			if (!jsonPathResult || !(typeof jsonPathResult[0] == 'string')) {
				console.log(`Couldn't find vp_token for path ${path}`);
				throw new Error(`Couldn't find vp_token for path ${path}`);
			}
			const vp_token = jsonPathResult[0];
			if (desc.format == VerifiableCredentialFormat.VC_SD_JWT) {
				const sdJwt = vp_token.split('~').slice(0, -1).join('~') + '~';
				const input_descriptor = rpState!.presentation_definition!.input_descriptors.filter((input_desc: any) => input_desc.id == desc.id)[0];
				if (!input_descriptor) {
					return { error: new Error("Input descriptor not found") };
				}

				const parsedSdJwt = SdJwt.fromCompact(sdJwt).withHasher(hasherAndAlgorithm);


				// kbjwt validation
				const kbJwtValidationResult = await verifyKbJwt(vp_token, { aud: rpState.audience, nonce: rpState.nonce });
				if (!kbJwtValidationResult) {
					const error = new Error("KB JWT validation failed");
					error.name = "PRESENTATION_RESPONSE:INVALID_KB_JWT";
					return { error };
				}
				console.info("Passed KBJWT verification...");

				// let error = "";
				// const errorCallback = (errorName: string) => {
				// 	error = errorName;
				// }

				const verifyCb: Verifier = async ({ header, message, signature }) => {
					if (header.alg !== SignatureAndEncryptionAlgorithm.ES256) {
						throw new Error('only ES256 is supported')
					}

					const publicKeyResolutionResult = await this.configurationService.getPublicKeyResolverChain().resolve(vp_token, VerifiableCredentialFormat.VC_SD_JWT);
					if ('error' in publicKeyResolutionResult) {
						return false;
					}

					if (!publicKeyResolutionResult.isTrusted) {
						return false;
					}
					const verificationResult = await jwtVerify(message + '.' + uint8ArrayToBase64Url(signature), publicKeyResolutionResult.publicKey).then(() => true).catch((err: any) => {
						console.log("Error verifying")
						console.error(err);
						// errorCallback(err.name);
						throw new Error(err);
					});
					return verificationResult;
				}

				try {
					const verificationResult = await parsedSdJwt.verify(verifyCb);
					const prettyClaims = await parsedSdJwt.getPrettyClaims();
	
					input_descriptor.constraints.fields.map((field: any) => {
						if (!presentationClaims[desc.id]) {
							presentationClaims[desc.id] = []; // initialize
						}
						const fieldPath = field.path[0]; // get first path
						const fieldName = (field as any).name;
						const value = String(JSONPath({ path: fieldPath, json: prettyClaims.vc as any ?? prettyClaims })[0]);
						if (!value) {
							const error = new Error(`Verification result: Not all values are present as requested from the presentation_definition`);
							error.name = "VALUE_NOT_FOUND";
							return { error: new Error("VALUE_NOT_FOUND") };
						}
	
						const splittedPath = fieldPath.split('.');
						const claimName = fieldName ? fieldName : splittedPath[splittedPath.length - 1];
						presentationClaims[desc.id].push({ key: fieldPath.split('.')[fieldPath.split('.').length - 1], name: claimName, value: typeof value == 'object' ? JSON.stringify(value) : value } as ClaimRecord);
					});
	
					if (!verificationResult.isSignatureValid) {
						const error = new Error(`Verification result ${JSON.stringify(verificationResult)}`);
						error.name = "SD_JWT_VERIFICATION_FAILURE";
						return { error: error };
					}
				}
				catch(err) {
					console.error("Verification error: ", err);
					if (err instanceof Error) {
						return { error: err };
					}
				}
			}
		}

		return { presentationClaims };
	}


	public async getPresentationBySessionIdOrPresentationDuringIssuanceSession(sessionId?: string, presentationDuringIssuanceSession?: string): Promise<{ status: true, presentations: unknown[], rpState: RelyingPartyState } | { status: false, error: Error }> {
		if (!sessionId && !presentationDuringIssuanceSession) {
			console.error("getPresentationBySessionIdOrPresentationDuringIssuanceSession: Nor sessionId nor presentationDuringIssuanceSession was given");
			const error = new Error("getPresentationBySessionIdOrPresentationDuringIssuanceSession: Nor sessionId nor presentationDuringIssuanceSession was given")
			return { status: false, error };
		}
		const rpState = sessionId ? await this.rpStateRepository.createQueryBuilder()
			.where("session_id = :session_id", { session_id: sessionId })
			.getOne() :
			await this.rpStateRepository.createQueryBuilder()
				.where("presentation_during_issuance_session = :presentation_during_issuance_session", { presentation_during_issuance_session: presentationDuringIssuanceSession })
				.getOne();

		if (!rpState) {
			console.error("Couldn't get rpState with the session_id " + sessionId);
			const error = new Error("Couldn't get rpState with the session_id " + sessionId);
			return { status: false, error };
		}

		if (!rpState.presentation_submission || !rpState.vp_token) {
			console.error("Presentation has not been sent. session_id " + sessionId);
			const error = new Error("Presentation has not been sent. session_id " + sessionId);
			return { status: false, error };
		}

		const vp_token = JSON.parse(base64url.decode(rpState.vp_token)) as string[] | string;

		const { presentationClaims, error } = await this.validateVpToken(vp_token, rpState.presentation_submission as any, rpState);

		if (error) {
			console.error(error)
			return { status: false, error };
		}
		if (!rpState.claims && presentationClaims) {
			rpState.claims = presentationClaims;
			await this.rpStateRepository.save(rpState);
		}
		if (rpState) {
			return { status: true, rpState, presentations: vp_token instanceof Array ? vp_token : [vp_token] };
		}
		const unkownErr = new Error("Uknown error");
		return { status: false, error: unkownErr };
	
	}

	public async getPresentationById(id: string): Promise<{ status: boolean, presentationClaims?: PresentationClaims, presentations?: unknown[] }> {
		const rpState = await this.rpStateRepository.createQueryBuilder('vp')
			.where("id = :id", { id: id })
			.getOne();

		if (!rpState?.vp_token || !rpState.claims) {
			return { status: false };
		}

		const vp_token = JSON.parse(base64url.decode(rpState.vp_token)) as string[] | string;

		if (rpState) {
			return { status: true, presentationClaims: rpState.claims, presentations: vp_token instanceof Array ? vp_token : [vp_token] };
		}

		return { status: false };
	}
}