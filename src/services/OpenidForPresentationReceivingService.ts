import { inject, injectable } from "inversify";
import { Request, Response } from 'express'
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "./interfaces";
import { VerifiableCredentialFormat } from "wallet-common/dist/types";
import { TYPES } from "./types";
import { compactDecrypt, CompactDecryptResult, exportJWK, generateKeyPair, importJWK, importPKCS8, SignJWT } from "jose";
import { randomUUID } from "crypto";
import base64url from "base64url";
import 'reflect-metadata';
import { JSONPath } from "jsonpath-plus";
import { Repository } from "typeorm";
import AppDataSource from "../AppDataSource";
import { config } from "../../config";
import fs from 'fs';
import path from "path";
import { ClaimRecord, PresentationClaims, RelyingPartyState } from "../entities/RelyingPartyState.entity";
import { generateRandomIdentifier } from "../lib/generateRandomIdentifier";
import * as z from 'zod';
import { initializeCredentialEngine } from "../lib/initializeCredentialEngine";
import { TransactionData } from "../TransactionData/TransactionData";
import { serializePresentationDefinition } from "../lib/serializePresentationDefinition";
import { DcqlPresentationResult } from 'dcql';
import { pemToBase64 } from "../util/pemToBase64";

const privateKeyPem = fs.readFileSync(path.join(__dirname, "../../../keys/pem.key"), 'utf-8').toString();
const leafCert = fs.readFileSync(path.join(__dirname, "../../../keys/pem.crt"), 'utf-8').toString();

enum ResponseMode {
	DIRECT_POST = 'direct_post',
	DIRECT_POST_JWT = 'direct_post.jwt'
}


const x5c = [
	pemToBase64(leafCert),
];

const ResponseModeSchema = z.nativeEnum(ResponseMode);

// @ts-ignore
const response_mode: ResponseMode = config?.presentationFlow?.response_mode ? ResponseModeSchema.parse(config?.presentationFlow?.response_mode) : ResponseMode.DIRECT_POST_JWT;

// const hasherAndAlgorithm: HasherAndAlgorithm = {
// 	hasher: (input: string) => createHash('sha256').update(input).digest(),
// 	algorithm: HasherAlgorithm.Sha256
// }

// function uint8ArrayToBase64Url(array: any) {
// 	// Convert the Uint8Array to a binary string
// 	let binaryString = '';
// 	array.forEach((byte: any) => {
// 		binaryString += String.fromCharCode(byte);
// 	});

// 	// Convert the binary string to a Base64 string
// 	let base64String = btoa(binaryString);

// 	// Convert the Base64 string to Base64URL format
// 	let base64UrlString = base64String
// 		.replace(/\+/g, '-') // Replace + with -
// 		.replace(/\//g, '_') // Replace / with _
// 		.replace(/=+$/, ''); // Remove trailing '='

// 	return base64UrlString;
// }

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

	async generateAuthorizationRequestURL(ctx: { req: Request, res: Response }, def: any, sessionId: string, callbackEndpoint?: string): Promise<{ url: URL; stateId: string }> {
		// create cookie and add it to response

		console.log("Presentation Request: Session id used for authz req ", sessionId);

		const nonce = randomUUID();
		const state = randomUUID();

		const responseUri = this.configurationService.getConfiguration().redirect_uri;
		const client_id = new URL(responseUri).hostname

		const [rsaImportedPrivateKey, rpEphemeralKeypair] = await Promise.all([
			importPKCS8(privateKeyPem, 'ES256'),
			generateKeyPair('ECDH-ES')
		]);
		const [exportedEphPub, exportedEphPriv] = await Promise.all([
			exportJWK(rpEphemeralKeypair.publicKey),
			exportJWK(rpEphemeralKeypair.privateKey)
		]);

		exportedEphPub.kid = generateRandomIdentifier(8);
		exportedEphPriv.kid = exportedEphPub.kid;
		exportedEphPub.use = 'enc';
		let transactionDataObject: any[] = [];
		if (def.input_descriptors) {
			transactionDataObject = await Promise.all(def.input_descriptors
				.filter(((input_desc: any) => input_desc._transaction_data_type !== undefined))
				.map(async (cred: any) => {
					if (!cred._transaction_data_type) {
						return null;
					}
					const txData = TransactionData(cred._transaction_data_type);
					if (!txData) {
						return null;
					}
					return await txData
						.generateTransactionDataRequestObject(cred.id);
				}));
		} else if (def.credentials) {
			transactionDataObject = await Promise.all(def.credentials
				.filter((cred: any) => cred._transaction_data_type !== undefined)
				.map(async (cred: any) => {
					if (!cred._transaction_data_type) {
						return null;
					}
					const txData = TransactionData(cred._transaction_data_type);
					if (!txData) {
						return null;
					}
					return await txData
						.generateTransactionDataRequestObject(cred.id);
				}));
		}

		transactionDataObject = transactionDataObject.filter((td) => td !== null);
		const signedRequestObject = await new SignJWT({
			response_uri: responseUri,
			aud: "https://self-issued.me/v2",
			iss: new URL(responseUri).hostname,
			client_id: "x509_san_dns:" + client_id,
			response_type: "vp_token",
			response_mode: response_mode,
			state: state,
			nonce: nonce,
			presentation_definition: def.input_descriptors ? serializePresentationDefinition(JSON.parse(JSON.stringify(def))) : null,
			dcql_query: def.credentials ? serializePresentationDefinition(JSON.parse(JSON.stringify(def))) : null,
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
					},
					"dc+sd-jwt": {
						"sd-jwt_alg_values": [
							"ES256",
						],
						"kb-jwt_alg_values": [
							"ES256",
						]
					},
					"mso_mdoc": {
						"alg": ["ES256"]
					}
				}
			},
			transaction_data: transactionDataObject.length > 0 ? transactionDataObject : undefined
		})
			.setIssuedAt()
			.setProtectedHeader({
				alg: 'ES256',
				x5c: x5c,
				typ: 'oauth-authz-req+jwt',
			})
			.sign(rsaImportedPrivateKey);
		// try to get the redirect uri from the authorization server state in case this is a Dynamic User Authentication during OpenID4VCI authorization code flow
		const redirectUri = ctx.req?.authorizationServerState?.redirect_uri ?? "openid4vp://cb";

		// verifierStates.set(state, { ephemeralKeyPair: rpEphemeralKeypair, callbackEndpoint, nonce, response_uri: responseUri, client_id: client_id, signedRequestObject, presentation_definition: presentationDefinition });


		const newRpState = new RelyingPartyState();
		newRpState.presentation_definition = def.input_descriptors ? def : null;
		newRpState.dcql_query = def.credentials ? def : null;
		newRpState.presentation_definition_id = def.id ? def.id : def.credentials[0].id;
		newRpState.date_created = new Date();
		newRpState.nonce = nonce;
		newRpState.state = state;
		newRpState.rp_eph_pub = exportedEphPub;
		newRpState.rp_eph_priv = exportedEphPriv;
		newRpState.rp_eph_kid = exportedEphPub.kid;
		newRpState.audience = "x509_san_dns:" + client_id;

		newRpState.session_id = sessionId;
		newRpState.signed_request = signedRequestObject;

		if (callbackEndpoint) {
			newRpState.callback_endpoint = callbackEndpoint;
		}


		await this.rpStateRepository.save(newRpState);

		const requestUri = config.url + "/verification/request-object?id=" + state;

		const redirectParameters = {
			client_id: "x509_san_dns:" + client_id,
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
			const result = await compactDecrypt(ctx.req.body.response, rp_eph_priv).then((r) => ({ data: r, err: null })).catch((err) => ({ data: null, err: err }));
			if (result.err) {
				const error = { error: "JWE Decryption failure", error_description: result.err };
				console.error(error);
				console.log("Received JWE headers: ", JSON.parse(base64url.decode(ctx.req.body.response.split('.')[0])));
				console.log("Received JWE: ", ctx.req.body.response);
				ctx.res.status(500).send(error);
				return;
			}

			const { protectedHeader, plaintext } = result.data as CompactDecryptResult;
			console.log("Protected header = ", protectedHeader)
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

			if (!payload.presentation_submission && !payload.vp_token) {
				throw new Error("Encrypted Response: presentation_submission and vp_token are missing");
			}
			rpState.response_code = base64url.encode(randomUUID());
			rpState.encrypted_response = ctx.req.body.response;
			rpState.presentation_submission = payload.presentation_submission;
			console.log("Encoding....")
			rpState.vp_token = base64url.encode(JSON.stringify(payload.vp_token));
			rpState.date_created = new Date();
			rpState.apv_jarm_encrypted_response_header = protectedHeader.apv && typeof protectedHeader.apv == 'string' ? protectedHeader.apv as string : null;
			rpState.apu_jarm_encrypted_response_header = protectedHeader.apu && typeof protectedHeader.apu == 'string' ? protectedHeader.apu as string : null;

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

	private async validatePresentationDefinitionVpToken(vp_token_list: string[] | string | Record<string, any> | string, presentation_submission: any, rpState: RelyingPartyState): Promise<{ presentationClaims?: PresentationClaims, error?: Error }> {
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
			if (desc.format == VerifiableCredentialFormat.DC_SDJWT || desc.format == VerifiableCredentialFormat.VC_SDJWT) {
				// const sdJwt = vp_token.split('~').slice(0, -1).join('~') + '~';
				const input_descriptor = rpState!.presentation_definition!.input_descriptors.filter((input_desc: any) => input_desc.id == desc.id)[0];
				if (!input_descriptor) {
					return { error: new Error("Input descriptor not found") };
				}

				try {
					const { credentialParsingEngine, sdJwtVerifier } = await initializeCredentialEngine();
					const verificationResultR = await sdJwtVerifier.verify({ rawCredential: vp_token, opts: { expectedAudience: rpState.audience, expectedNonce: rpState.nonce } })
					const parseResult = await credentialParsingEngine.parse({ rawCredential: vp_token })
					const prettyClaims = parseResult.success === true ? parseResult.value.signedClaims : null;

					if (verificationResultR.success === false) {
						const error = new Error(`Verification result ${JSON.stringify(verificationResultR.error)}`);
						error.name = JSON.stringify(verificationResultR.error);
						return { error: error };
					}
					if (!prettyClaims) {
						return { error: new Error(JSON.stringify(parseResult.success === false && parseResult.error)) };
					}
					try {
						const [kbjwt,] = vp_token.split('~').reverse();
						const [_kbjwtEncodedHeader, kbjwtEncodedPayload, _kbjwtSig] = kbjwt.split('.');

						const kbjwtPayload = JSON.parse(base64url.decode(kbjwtEncodedPayload)) as Record<string, unknown>;
						if (Object.keys(kbjwtPayload).includes('transaction_data_hashes') && input_descriptor._transaction_data_type !== undefined) {
							console.log("Parsing transaction data response...");
							const txData = TransactionData(input_descriptor._transaction_data_type);
							if (!txData) {
								return { error: new Error("specific transaction_data not supported error") };
							}
							const validationResult = await txData.validateTransactionDataResponse(input_descriptor.id, {
								transaction_data_hashes: (kbjwtPayload as any).transaction_data_hashes as string[],
								transaction_data_hashes_alg: (kbjwtPayload as any).transaction_data_hashes_alg as string[] | undefined
							});
							if (!validationResult) {
								return { error: new Error("transaction_data validation error") };
							}
							console.log("VALIDATED TRANSACTION DATA");
						}
						else if (input_descriptor._transaction_data_type !== undefined) {
							return { error: new Error("transaction_data_hashes is missing from transaction data response") };
						}
					}
					catch (e) {
						console.error(e);
						return { error: new Error("transaction_data validation error") };

					}

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


				}
				catch (err) {
					console.error("Verification error: ", err);
					if (err instanceof Error) {
						return { error: err };
					}
				}
			}
			else if (desc.format == VerifiableCredentialFormat.MSO_MDOC && rpState.apu_jarm_encrypted_response_header) {
				const receivedMdocNonce = base64url.decode(rpState.apu_jarm_encrypted_response_header);
				console.log("Received mdoc nonce = ", receivedMdocNonce);
				console.log("Verifcation Opts = ", {
					expectedAudience: rpState.audience,
					expectedNonce: rpState.nonce,
					holderNonce: receivedMdocNonce,
					responseUri: this.configurationService.getConfiguration().redirect_uri,
				});

				const ce = await initializeCredentialEngine();
				const verificationResult = await ce.msoMdocVerifier.verify({
					rawCredential: vp_token,
					opts: {
						expectedAudience: rpState.audience,
						expectedNonce: rpState.nonce,
						holderNonce: receivedMdocNonce,
						responseUri: this.configurationService.getConfiguration().redirect_uri,
					}
				});
				if (!verificationResult.success) {
					return {
						error: new Error(verificationResult.error)
					}
				}
				// const { holderPublicKey } = verificationResult.value;


				const parsingResult = await ce.credentialParsingEngine.parse({
					rawCredential: vp_token
				});

				if (!parsingResult.success) {
					return {
						error: new Error(parsingResult.error)
					}
				}
				const parsedCredential = parsingResult.value;
				console.log("Parsed credential = ", parsedCredential);
				const definition = rpState.presentation_definition;

				const fieldNamesWithValues = definition.input_descriptors[0].constraints.fields.map((field: any) => {
					const key = field.path.map((possiblePath: string) => possiblePath.split('.')[possiblePath.split('.').length - 1]);
					const signedClaimsWithDoctype = {};
					// @ts-ignore
					signedClaimsWithDoctype[definition.input_descriptors[0].id] = { ...parsedCredential.signedClaims };
					console.log("Signed claims with doctype = ", signedClaimsWithDoctype)
					const values = field.path.map((possiblePath: string) => JSONPath({ path: possiblePath, json: signedClaimsWithDoctype })[0]);
					const val = values.filter((v: any) => v != undefined || v != null)[0]; // get first value that is not undefined
					return val ? { key, name: (field as any).name as string, value: typeof val == 'object' ? JSON.stringify(val) : val as string } : undefined;
				});
				console.log("Fieldnames with values = ", fieldNamesWithValues)
				// if (fieldNamesWithValues.includes(undefined)) {
				// 	return { error: new Error("INSUFFICIENT_CREDENTIALS"), error_description: new Error("Insufficient credentials") };
				// }

				for (const item of fieldNamesWithValues as Array<{ key: string, name: string; value: string } | undefined>) {
					if (item) { // Check if item is not undefined
						const { key, name, value } = item;
						presentationClaims[desc.id].push({ key, name, value });
					}
				}
			}
		}

		return { presentationClaims };
	}

	private async validateDcqlVpToken(
		vp_token_list: any,
		dcql_query: any,
		rpState: RelyingPartyState
	): Promise<{ presentationClaims?: PresentationClaims, error?: Error }> {
		const presentationClaims: PresentationClaims = {};
		const ce = await initializeCredentialEngine();

		for (const descriptor of dcql_query.credentials) {
			const vp = vp_token_list[descriptor.id];
			if (!vp) {
				return { error: new Error(`Missing VP for descriptor ${descriptor.id}`) };
			}

			try {
				// detect if SD-JWT (has ~) or mdoc (CBOR-encoded)
				if (typeof vp === 'string' && vp.includes('~')) {
					// ========== SD-JWT ==========
					try {
						const [kbjwt] = vp.split('~').reverse();
						const [_kbjwtEncodedHeader, kbjwtEncodedPayload, _kbjwtSig] = kbjwt.split('.');
						const kbjwtPayload = JSON.parse(base64url.decode(kbjwtEncodedPayload)) as Record<string, unknown>;
						if (Object.keys(kbjwtPayload).includes('transaction_data_hashes') && descriptor._transaction_data_type !== undefined) {
							const txData = TransactionData(descriptor._transaction_data_type);
							if (!txData) {
								return { error: new Error("specific transaction_data not supported error") };
							}
							const validationResult = await txData.validateTransactionDataResponse(descriptor.id, {
								transaction_data_hashes: (kbjwtPayload as any).transaction_data_hashes as string[],
								transaction_data_hashes_alg: (kbjwtPayload as any).transaction_data_hashes_alg as string[] | undefined
							});
							if (!validationResult) {
								return { error: new Error("transaction_data validation error") };
							}
							console.log("VALIDATED TRANSACTION DATA");
						}
						else if (descriptor._transaction_data_type !== undefined) {
							return { error: new Error("transaction_data_hashes is missing from transaction data response") };
						}
					} catch (e) {
						console.error(e);
						return { error: new Error("transaction_data validation error") };
					}
					const verificationResult = await ce.sdJwtVerifier.verify({
						rawCredential: vp,
						opts: {
							expectedAudience: rpState.audience,
							expectedNonce: rpState.nonce,
						},
					});
					if (!verificationResult.success) {
						return { error: new Error(`SD-JWT verification failed for ${descriptor.id}: ${verificationResult.error}`) };
					}

					const parseResult = await ce.credentialParsingEngine.parse({ rawCredential: vp });
					if (!parseResult.success) {
						return { error: new Error(`Parsing SD-JWT failed for ${descriptor.id}: ${parseResult.error}`) };
					}

					const signedClaims = parseResult.value.signedClaims;
					const shaped = {
						vct: signedClaims.vct,
						credential_format: VerifiableCredentialFormat.DC_SDJWT,
						claims: signedClaims,
						cryptographic_holder_binding: true
					};

					const dcqlResult = DcqlPresentationResult.fromDcqlPresentation(
						{ [descriptor.id]: [shaped] },
						{ dcqlQuery: dcql_query }
					);
					if (!dcqlResult.credential_matches[descriptor.id]?.success) {
						return { error: new Error(`DCQL validation failed for ${descriptor.id}`) };
					}

					const output = dcqlResult.credential_matches[descriptor.id].valid_credentials?.[0].meta.output as any;
					if (
						output.credential_format === VerifiableCredentialFormat.VC_SDJWT ||
						output.credential_format === VerifiableCredentialFormat.DC_SDJWT
					) {
						const claimsObject = dcqlResult.credential_matches[descriptor.id].valid_credentials?.[0].claims as any;
						presentationClaims[descriptor.id] = Object.entries(claimsObject.valid_claim_sets[0].output).map(([key, value]) => ({
							key,
							name: key,
							value: typeof value === 'object' ? JSON.stringify(value) : String(value),
						}));
					} else {
						return { error: new Error(`Unexpected credential_format for descriptor ${descriptor.id}`) };
					}
				} else {
					// ========== mdoc ==========
					const verificationResult = await ce.msoMdocVerifier.verify({
						rawCredential: vp,
						opts: {
							expectedAudience: rpState.audience,
							expectedNonce: rpState.nonce,
							holderNonce: rpState.apu_jarm_encrypted_response_header
								? base64url.decode(rpState.apu_jarm_encrypted_response_header)
								: undefined,
							responseUri: this.configurationService.getConfiguration().redirect_uri,
						},
					});
					if (!verificationResult.success) {
						return { error: new Error(`mDoc verification failed for ${descriptor.id}: ${verificationResult.error}`) };
					}

					const parseResult = await ce.credentialParsingEngine.parse({ rawCredential: vp });
					if (!parseResult.success) {
						return { error: new Error(`Parsing mDoc failed for ${descriptor.id}: ${parseResult.error}`) };
					}
					const signedClaims = parseResult.value.signedClaims;
					const shaped = {
						credential_format: VerifiableCredentialFormat.MSO_MDOC,
						doctype: descriptor.meta?.doctype_value,
						cryptographic_holder_binding: true,
						namespaces: signedClaims
					};

					const dcqlResult = DcqlPresentationResult.fromDcqlPresentation(
						{ [descriptor.id]: [shaped] },
						{ dcqlQuery: dcql_query }
					);

					if (!dcqlResult.credential_matches[descriptor.id]?.success) {
						return { error: new Error(`DCQL validation failed for mdoc descriptor ${descriptor.id}`) };
					}
					const output = dcqlResult.credential_matches[descriptor.id].valid_credentials?.[0].meta.output as any;
					if (output.credential_format === VerifiableCredentialFormat.MSO_MDOC) {
						const claimsObject = dcqlResult.credential_matches[descriptor.id].valid_credentials?.[0].claims as any;
						if (!claimsObject) {
							return { error: new Error(`No claims found in mdoc for doctype ${descriptor.meta?.doctype_value}`) };
						}
						presentationClaims[descriptor.id] = Object.entries(claimsObject.valid_claim_sets[0].output[descriptor.meta?.doctype_value]).map(([key, value]) => ({
							key,
							name: key,
							value: typeof value === 'object' ? JSON.stringify(value) : String(value),
						}));
					} else {
						return { error: new Error(`Unexpected mdoc credential_format in output for descriptor ${descriptor.id}`) };
					}
				}
			} catch (e) {
				console.error(`Error processing descriptor ${descriptor.id}:`, e);
				return { error: new Error(`Internal error verifying or parsing VP for descriptor ${descriptor.id}`) };
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

		if (!rpState.vp_token) {
			console.error("Presentation has not been sent. session_id " + sessionId);
			const error = new Error("Presentation has not been sent. session_id " + sessionId);
			return { status: false, error };
		}

		const vp_token = JSON.parse(base64url.decode(rpState.vp_token)) as string[] | string | Record<string, string>;

		let presentationClaims;
		let error: Error | undefined;
		if (rpState.dcql_query) {
			const result = await this.validateDcqlVpToken(vp_token as any, rpState.dcql_query, rpState);
			presentationClaims = result.presentationClaims;
			error = result.error;
		} else {
			const result = await this.validatePresentationDefinitionVpToken(vp_token, rpState.presentation_submission as any, rpState);
			presentationClaims = result.presentationClaims;
			error = result.error;
		}

		if (error) {
			console.error(error)
			return { status: false, error };
		}
		if (!rpState.claims && presentationClaims) {
			rpState.claims = presentationClaims;
			await this.rpStateRepository.save(rpState);
		}
		if (rpState) {
			return {
				status: true,
				rpState,
				presentations: Array.isArray(vp_token) ? vp_token : typeof vp_token === 'object' ? Object.values(vp_token) : [vp_token]
			};
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
