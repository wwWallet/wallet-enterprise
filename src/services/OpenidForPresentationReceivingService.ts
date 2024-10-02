import { inject, injectable } from "inversify";
import { Request , Response} from 'express'
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "./interfaces";
import { VerifiableCredentialFormat } from "../types/oid4vci";
import { TYPES } from "./types";
import { importJWK, importPKCS8, importX509, jwtVerify, SignJWT } from "jose";
import { X509Certificate, createHash, randomUUID } from "crypto";
import base64url from "base64url";
import 'reflect-metadata';
import { JSONPath } from "jsonpath-plus";
import { Repository } from "typeorm";
import { ClaimRecord, PresentationClaims, VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
import AppDataSource from "../AppDataSource";
import config from "../../config";
import { HasherAlgorithm, HasherAndAlgorithm, SdJwt, SignatureAndEncryptionAlgorithm, Verifier } from "@sd-jwt/core";
import fs from 'fs';
import path from "path";
import crypto from 'node:crypto';

const privateKeyPem = fs.readFileSync(path.join(__dirname, "../../../keys/pem.server.key"), 'utf-8').toString();
const x5c = JSON.parse(fs.readFileSync(path.join(__dirname, "../../../keys/x5c.server.json")).toString()) as Array<string>;


const hasherAndAlgorithm: HasherAndAlgorithm = {
	hasher: (input: string) => createHash('sha256').update(input).digest(),
	algorithm: HasherAlgorithm.Sha256
}


type VerifierState = {
	callbackEndpoint?: string;
	presentation_definition: any;
	nonce: string;
	response_uri: string;
	client_id: string;
	signedRequestObject: string;
}

const verifierStates = new Map<string, VerifierState>();

// const CLOCK_TOLERANCE = '15 minutes';

const nonces = new Map<string, string>(); // key: nonce, value: verifierStateId


async function verifyCertificateChain(rootCert: string, pemCertChain: string[]) {
	const x509TrustAnchor = new X509Certificate(rootCert);
	const isLastCertTrusted = new X509Certificate(pemCertChain[pemCertChain.length - 1]).verify(x509TrustAnchor.publicKey);
	if (!isLastCertTrusted) {
		return false;
	}
	for (let i = 0; i < pemCertChain.length; i++) {
		if (pemCertChain[i + 1]) {
			const isTrustedCert = new X509Certificate(pemCertChain[i]).verify(new X509Certificate(pemCertChain[i + 1]).publicKey);
			if (!isTrustedCert) {
				return false;
			}
		}
	}
	return true;
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
	private verifiablePresentationRepository: Repository<VerifiablePresentationEntity> = AppDataSource.getRepository(VerifiablePresentationEntity);
	// private authorizationServerStateRepository: Repository<AuthorizationServerState> = AppDataSource.getRepository(AuthorizationServerState);

	constructor(
		@inject(TYPES.VerifierConfigurationServiceInterface) private configurationService: VerifierConfigurationInterface,
	) {}

	metadataRequestHandler(_ctx: { req: Request, res: Response }): Promise<void> {
		throw new Error("Method not implemented.");
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


	public async getSignedRequestObject(ctx: { req: Request, res: Response }): Promise<any> {
		if (!ctx.req.query['id'] || typeof ctx.req.query['id'] != 'string') {
			return ctx.res.status(500).send({ error: "id does not exist on query params" });
		}
		const verifierStateId = ctx.req.query['id'] as string;
		const verifierState = verifierStates.get(verifierStateId);
		if (!verifierState) {
			return ctx.res.status(500).send({ error: "verifier state could not be fetched with this id" });
		}
		return ctx.res.send(verifierState.signedRequestObject);
	}

	
	async generateAuthorizationRequestURL(ctx: { req: Request, res: Response }, presentationDefinition: any, callbackEndpoint?: string): Promise<{ url: URL; stateId: string }> {
		const nonce = randomUUID();
		const stateId = randomUUID();
		nonces.set(nonce, stateId);

		console.log("Callback endpoint = ", callbackEndpoint)

		const responseUri = this.configurationService.getConfiguration().redirect_uri;
		const client_id = new URL(responseUri).hostname
		// const privateKey = await importJWK(privateKeyJwk, 'ES256');
		const privateKey = await importPKCS8(privateKeyPem, 'RS256');

		const signedRequestObject = await new SignJWT({
			response_uri: responseUri,
			aud: "https://self-issued.me/v2",
			iss: new URL(responseUri).hostname,
			client_id_scheme: "x509_san_dns",
			client_id: client_id,
			response_type: "vp_token",
			response_mode: "direct_post",
			state: stateId,
			nonce: nonce,
			presentation_definition: presentationDefinition,
			client_metadata: {
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
			.sign(privateKey);
		// try to get the redirect uri from the authorization server state in case this is a Dynamic User Authentication during OpenID4VCI authorization code flow
		const redirectUri = ctx.req?.authorizationServerState?.redirect_uri ?? "openid4vp://cb";

		verifierStates.set(stateId, { callbackEndpoint, nonce, response_uri: responseUri, client_id: client_id, signedRequestObject, presentation_definition: presentationDefinition });

		console.log("State id on send = ", stateId)
		const requestUri = config.url + "/verification/request-object?id=" + stateId;

		const redirectParameters = {
			client_id: client_id,
			request_uri: requestUri
		};

		const searchParams = new URLSearchParams(redirectParameters);
		const authorizationRequestURL = new URL(redirectUri + "?" + searchParams.toString()); // must be openid4vp://cb
		
		console.log("AUTHZ REQ = ", authorizationRequestURL);
		return { url: authorizationRequestURL, stateId };
	}


	async responseHandler(ctx: { req: Request, res: Response }): Promise<void> {
		const { vp_token, state, presentation_submission } = ctx.req.body;
		// let presentationSubmissionObject: PresentationSubmission | null = qs.parse(decodeURI(presentation_submission)) as any;
		let presentationSubmissionObject: any | null = presentation_submission ? JSON.parse(decodeURI(presentation_submission)) as any : null;

		console.log("Presentation submission object = ", presentationSubmissionObject)

		if (!state) {
			console.log("Missing state param");
			ctx.res.status(401).send({ error: "Missing state param" });
			return;
		}

		console.log("responseHandler: state = ", state)
		const verifierState = verifierStates.get(state);
		if (!verifierState) {
			console.log("Error getting the verifier state");
			ctx.res.status(401).send({ error: "Error getting the verifier state" });
			return;
		}
	

		if (!vp_token) {
			console.log("Missing state param")
			ctx.res.status(401).send({ error: "Missing state param" });
			return;
		}

		try {
			if (presentationSubmissionObject?.descriptor_map[0].format == 'vc+sd-jwt') {
				await (async function validateKbJwt() {
					const sdJwt = vp_token.split('~').slice(0, -1).join('~') + '~';
					const kbJwt = vp_token.split('~')[vp_token.split('~').length - 1] as string;
					const { sd_hash, nonce, aud } = JSON.parse(base64url.decode(kbJwt.split('.')[1])) as any;
					async function calculateHash(text: string) {
						const encoder = new TextEncoder();
						const data = encoder.encode(text);
						const hashBuffer = await crypto.webcrypto.subtle.digest('SHA-256', data);
						const base64String = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
						const base64UrlString = base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
						return base64UrlString;
					}
					if (await calculateHash(sdJwt) != sd_hash) {
						throw new Error("Wrong sd_hash");
					}
					if (aud != verifierState.client_id) {
						throw new Error("Wrong aud");
					}
					let verifierStateIdByNonce = nonces.get(nonce as string);
					if (!verifierStateIdByNonce) {
						throw new Error("Invalid nonce");
					}
					return { sdJwt };
				})();
			}
			// perform verification of vp_token
			let msg = {};
			if (state) {
				msg = { ...msg, state } as any;
			}
			const { presentationClaims, error, error_description } = await this.validateVpToken(vp_token, presentationSubmissionObject as any, verifierState);
			
			if (error && error_description && verifierState.callbackEndpoint) {
				msg = { ...msg, error: error.message, error_description: error_description?.message };
				console.error(msg);
				// const searchParams = new URLSearchParams(msg);
				// ctx.res.redirect(verifierState.callbackEndpoint + searchParams);
				ctx.res.status(500).send({ ...msg })
				return;
			}


			// store presentation
			const newVerifiablePresentation = new VerifiablePresentationEntity()
			newVerifiablePresentation.presentation_definition_id = (JSON.parse(presentation_submission) as any).definition_id;
			newVerifiablePresentation.claims = presentationClaims ?? null;
			newVerifiablePresentation.status = true;
			newVerifiablePresentation.raw_presentation = vp_token;
			newVerifiablePresentation.presentation_submission = presentationSubmissionObject;
			newVerifiablePresentation.date = new Date();
			newVerifiablePresentation.state = state as string;
			await this.verifiablePresentationRepository.save(newVerifiablePresentation);

			console.error(msg);
			//@ts-ignore
			const searchParams = new URLSearchParams(msg);

			console.log("Redirecting to = ", verifierState.callbackEndpoint + '?' + searchParams)
			ctx.res.send({ redirect_uri: verifierState.callbackEndpoint + '?' + searchParams })
		}
		catch(e) {
			console.error(e)
			throw new Error("OpenID4VP Authorization Response failed. " + JSON.stringify(e));
		}		
	}

	private async validateVpToken(vp_token: string, presentation_submission: any, verifierState: VerifierState): Promise<{ presentationClaims?: PresentationClaims, error?: Error, error_description?: Error }> {
		let presentationClaims: PresentationClaims = {};

		for (const desc of presentation_submission.descriptor_map) {
			if (!presentationClaims[desc.id]) {
				presentationClaims[desc.id] = [];
			}


			if (desc.format == VerifiableCredentialFormat.VC_SD_JWT) {
				const sdJwt = vp_token.split('~').slice(0, -1).join('~') + '~';
				const kbJwt = vp_token.split('~')[vp_token.split('~').length - 1] as string;
				const path = desc?.path as string;
				console.log("Path = ", path)

				const input_descriptor = verifierState!.presentation_definition!.input_descriptors.filter((input_desc: any) => input_desc.id == desc.id)[0];
				if (!input_descriptor) {
					return { error: new Error("Input descriptor not found") };
				}
				const requiredClaimNames = input_descriptor.constraints.fields.map((field: any) => {
					const fieldPath = field.path[0];
					const splittedPath = fieldPath.split('.');
					return splittedPath[splittedPath.length - 1]; // return last part of the path
				});

				const parsedSdJwt = SdJwt.fromCompact(sdJwt).withHasher(hasherAndAlgorithm);

				const jwtPayload = (JSON.parse(base64url.decode(sdJwt.split('.')[1])) as any);

				// kbjwt validation
				try {
					const { alg } = JSON.parse(base64url.decode(kbJwt.split('.')[0])) as { alg: string }; 
					const publicKey = await importJWK(jwtPayload.cnf.jwk, alg);
					await jwtVerify(kbJwt, publicKey);
				}
				catch(err) {
					return { error: new Error("PRESENTATION_RESPONSE:INVALID_KB_JWT"), error_description: new Error("KB JWT validation failed") };
				}



				const verifyCb: Verifier = async ({ header, message, signature }) => {
					if (header.alg !== SignatureAndEncryptionAlgorithm.ES256) {
						throw new Error('only ES256 is supported')
					}
					if (header['x5c'] && header['x5c'] instanceof Array && header['x5c'][0]) {
						const pemCerts = header['x5c'].map(cert => {
							const pemCert = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`;
							return pemCert;
						});

						// check if at least one root certificate verifies this credential
						const result: boolean[] = await Promise.all(config.trustedRootCertificates.map(async (rootCert: string) => {
							return verifyCertificateChain(rootCert, pemCerts);
						}));


						if (config.trustedRootCertificates.length != 0 && !result.includes(true)) {
							console.log("Chain is not trusted");
							return false;
						}
						console.info("Chain is trusted");
						const cert = await importX509(pemCerts[0], 'ES256');
						const verificationResult = await jwtVerify(message + '.' + uint8ArrayToBase64Url(signature), cert).then(() => true).catch((err: any) => {
							console.log("Error verifying")
							console.error(err);
							return false;
						});
						console.log("JWT verification result = ", verificationResult);
						return verificationResult;
					}
					return false;
				}

				const verificationResult = await parsedSdJwt.verify(verifyCb, requiredClaimNames);
				const prettyClaims = await parsedSdJwt.getPrettyClaims();

				input_descriptor.constraints.fields.map((field: any) => {
					if (!presentationClaims[desc.id]) {
						presentationClaims[desc.id] = []; // initialize
					}
					const fieldPath = field.path[0]; // get first path
					const fieldName = (field as any).name;
					const value = String(JSONPath({ path: fieldPath, json: prettyClaims.vc as any ?? prettyClaims })[0]);
					const splittedPath = fieldPath.split('.');
					const claimName = fieldName ? fieldName : splittedPath[splittedPath.length - 1];
					presentationClaims[desc.id].push({ name: claimName, value: typeof value == 'object' ? JSON.stringify(value) : value } as ClaimRecord);
				});

				if (!verificationResult.isSignatureValid || !verificationResult.areRequiredClaimsIncluded) {
					return { error: new Error("SD_JWT_VERIFICATION_FAILURE"), error_description: new Error(`Verification result ${JSON.stringify(verificationResult)}`) };
				}
			}
		}

		return { presentationClaims };
	}


	public async getPresentationByState(state: string): Promise<{ status: true, vp: VerifiablePresentationEntity } | { status: false }> {
		const vp = await this.verifiablePresentationRepository.createQueryBuilder('vp')
			.where("state = :state", { state: state })
			.getOne();
		
		if (!vp?.raw_presentation || !vp.claims) {
			return { status: false };
		}

		if (vp) 
			return { status: true, vp };
		else
			return { status: false };
	}

	public async getPresentationById(id: string): Promise<{ status: boolean, presentationClaims?: PresentationClaims, rawPresentation?: string }> {
		const vp = await this.verifiablePresentationRepository.createQueryBuilder('vp')
			.where("id = :id", { id: id })
			.getOne();

		if (!vp?.raw_presentation || !vp.claims) {
			return { status: false };
		}

		if (vp)
			return { status: true, presentationClaims: vp.claims, rawPresentation: vp?.raw_presentation };
		else
			return { status: false };
	}
}