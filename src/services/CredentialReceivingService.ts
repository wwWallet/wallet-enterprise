import { inject, injectable } from "inversify";
import { CredentialReceiving, WalletKeystore } from "./interfaces";
import 'reflect-metadata';
import { TYPES } from "./types";
import { generateCodeChallengeFromVerifier, generateCodeVerifier } from "../util/oid4vci";
import config from "../../config";
import axios from "axios";
import base64url from "base64url";
import { SignJWT } from "jose";
import qs from "qs";
import { TokenResponseSchemaType } from "../types/oid4vci";

@injectable()
export class CredentialReceivingService implements CredentialReceiving {

	readonly walletIdentifier = "conformant";
	walletDID: string = "";

	constructor(
		@inject(TYPES.FilesystemKeystoreService) private walletKeystoreService: WalletKeystore,
	) {

		this.walletKeystoreService.getPublicKeyJwk(this.walletIdentifier).then((res) => {
			const walletDID = res.jwk.kid?.split('#')[0];
			if (!walletDID) {
				throw new Error("Could not get wallet DID");
			}
			this.walletDID = walletDID;
		})
	}

	async sendAuthorizationRequest(): Promise<any> {
		const authorizationEndpoint = "https://api-conformance.ebsi.eu/conformance/v3/auth-mock/authorize";
		const authorizationDetails = [
			{
				type: "openid_credential",
				types: [ "VerifiableCredential","VerifiableAttestation","CTIssueQualificationCredential"],
				format: "jwt_vc",
				locations: ["https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"]
			}
		];
		const authorizationRequestURL = new URL(authorizationEndpoint);
		authorizationRequestURL.searchParams.append("scope", "openid");
		authorizationRequestURL.searchParams.append("client_id", this.walletDID);
		
		authorizationRequestURL.searchParams.append("redirect_uri", config.url);

		authorizationRequestURL.searchParams.append("authorization_details", JSON.stringify(authorizationDetails));
		const code_verifier = generateCodeVerifier();
		const code_challenge = await generateCodeChallengeFromVerifier(code_verifier);
		authorizationRequestURL.searchParams.append("code_challenge", code_challenge);
		authorizationRequestURL.searchParams.append("code_challenge_method", "S256");
		authorizationRequestURL.searchParams.append("response_type", "code");
		// authorizationRequestURL.searchParams.append("issuer_state", issuer_state);
		const client_metadata = {
			jwks_uri: config.url + "/jwks",
			vp_formats_supported: {
				jwt_vp: {
					alg: ["ES256"]
				}
			},
			response_types_supported: [ "vp_token", "id_token" ]
		};
		authorizationRequestURL.searchParams.append("client_metadata", JSON.stringify(client_metadata));
		const idTokenRequestUrlString = await axios.get(authorizationRequestURL.toString(), {
			maxRedirects: 0
		}).catch(e => {
			if (e.response) {
				return e.response.headers["location"]
			}
		});
		const idTokenRequestUrl = new URL(idTokenRequestUrlString);

		
		console.log(idTokenRequestUrl.searchParams)

		const { redirect_to } = await this.parseIdTokenRequest(idTokenRequestUrlString).then(success => {
			return success
		}).catch((e) => {
			console.error(e)
			return { redirect_to: null }
		})
		const code = new URL(redirect_to as string).searchParams.get('code') as string;
		const { access_token, c_nonce } = await this.tokenRequest(code, code_verifier);
		await this.credentialRequest(access_token, c_nonce)

	}

	private async credentialRequest(access_token: string, c_nonce: string) {
		const signJwt = new SignJWT({ nonce: c_nonce, aud: "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock" })
			
		const { jws } = await this.walletKeystoreService.signJwt("conformant", signJwt, "openid4vci-proof+jwt");
		try {
				const response = await axios.post("https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/credential",
				{ proof: { proof_type: "jwt", jwt: jws }, types: [ "VerifiableCredential","VerifiableAttestation","CTIssueQualificationCredential"], format: "jwt_vc"},
				{ headers: { "authorization": `Bearer ${access_token}`}}
			) as any;
			console.log("Credential = ", response.data);
		}
		catch(e: any) {
			console.log(e.response.data)
		}

	}

	private async parseIdTokenRequest(authorizationRequestURL: string): Promise<{ redirect_to: string }> {

		let client_id: string,
			redirect_uri: string,
			nonce: string,
			presentation_definition: any | null,
			state: string | null,
			request_uri: string | null;

		console.log("Pure params = ", new URL(authorizationRequestURL))
		try {
			const searchParams = await this.authorizationRequestSearchParams(authorizationRequestURL);
			console.log("SEARCH params = ", searchParams)
			client_id = searchParams.client_id;
			redirect_uri = searchParams.redirect_uri;
			nonce = searchParams.nonce;
			state = searchParams.state;
			request_uri = searchParams.request_uri
			request_uri
		}
		catch(error) {
			throw new Error(`Error fetching authorization request search params: ${error}`);
		}

		if (presentation_definition) {
			throw "This is not an id token request"
		}

		const did = (await this.walletKeystoreService.getPublicKeyJwk("conformant")).jwk.kid?.split('#')[0] as string;
		const signJwt = new SignJWT({ nonce: nonce })
			.setSubject(did)
			.setIssuer(did)
			.setExpirationTime('1m')
			.setAudience(client_id)
			.setIssuedAt();
	
		const { jws } = await this.walletKeystoreService.signJwt("conformant", signJwt, "JWT");
		const params = {
			id_token: jws,
			state: state,
			// issuer_state: issuer_state
		};
		

		console.log("Params = ", params)
		console.log("RedirectURI = ", redirect_uri)
		const encodedParams = qs.stringify(params);
		const { newLocation } = await axios.post(redirect_uri, encodedParams, { maxRedirects: 0, headers: { "Content-Type": "application/x-www-form-urlencoded" }})
			.then(success => {
				console.log("url = ", success.config.headers)
				console.log("body = ", success.data)
				console.log(success.status)
				const msg = {
					error: "Direct post error",
					error_description: "Failed to redirect after direct post"
				};
				console.error(msg);
				// console.log("Sucess = ", success.data)
				return { newLocation: null }
			})
			.catch(e => {
				console.log("ERR");
				console.log("UNKNOWN")
				if (e.response) {
					console.log("UNKNOWN = ", e.response.data)

					if (e.response.headers.location) {
						console.log("Loc: ", e.response.headers.location);
						const newLocation = e.response.headers.location as string;
						console.error("Body of Error = ", e.response.data)
						const url = new URL(newLocation)
						console.log("Pure url of loc: ", url)
						return { newLocation }
					}
					else {
						return { newLocation: null }
					}

				}
				return { newLocation: null };
			});
		// const id_token = await new SignJWT({ nonce: nonce })
		// 	.setAudience(client_id)
		// 	.setIssuedAt()
		// 	.setIssuer(did)
		// 	.setSubject(did)
		// 	.setExpirationTime('1h')
		// 	.setProtectedHeader({ kid: did+"#"+did.split(":")[2], typ: 'JWT', alg: walletKey.alg })
		// 	.sign(await importJWK(walletKey.privateKey, walletKey.alg));
		
		if (!newLocation) {
			throw new Error("Could not redirect");
		}	
		return { redirect_to: newLocation }

	}


		/**
	 * Handle Authorization Request search Parameters.
	 * @param authorizationRequest a string of the authorization request URL
	 * @returns An object containing Authorization Request Parameters
	 */
		private async authorizationRequestSearchParams(authorizationRequest: string) {
	
			// let response_type, client_id, redirect_uri, scope, response_mode, presentation_definition, nonce;
	
			// Attempt to convert authorizationRequest to URL form, in order to parse searchparams easily
			// An error will be thrown if the URL is invalid
			let authorizationRequestUrl: URL;
			try {
				authorizationRequestUrl = new URL(authorizationRequest);
			}
			catch(error) {
				throw new Error(`Invalid Authorization Request URL: ${error}`);
			}
	
			// const variables are REQUIRED authorization request parameters and they must exist outside the "request" parameter
			const response_type = authorizationRequestUrl.searchParams.get("response_type");
			const client_id = authorizationRequestUrl.searchParams.get("client_id");
			const redirect_uri = authorizationRequestUrl.searchParams.get("redirect_uri");
			const scope = authorizationRequestUrl.searchParams.get("scope");
			let response_mode = authorizationRequestUrl.searchParams.get("response_mode");
			let nonce = authorizationRequestUrl.searchParams.get("nonce");
			let state = authorizationRequestUrl.searchParams.get("state") as string | null;
			let request_uri = authorizationRequestUrl.searchParams.get("request_uri") as string | null;
			const request = authorizationRequestUrl.searchParams.get("request");
	
		
			try {
				if(request) {
					let requestPayload: any;
					try {
						requestPayload = JSON.parse(base64url.decode(request.split('.')[1]));
					}
					catch(error) {
						throw new Error(`Invalid Request parameter: Request is not a jwt. Details: ${error}`);
					}
	
					if(requestPayload.response_type && requestPayload.response_type !== response_type) {
						throw new Error('Request JWT response_type and authorization request response_type search param do not match');
					}
	
					if(requestPayload.scope && requestPayload.scope !== scope) {
						throw new Error('Request JWT scope and authorization request scope search param do not match');
					}
	
					if(requestPayload.client_id && requestPayload.client_id !== client_id) {
						throw new Error('Request JWT client_id and authorization request client_id search param do not match');
					}
	
					if(requestPayload.redirect_uri && requestPayload.redirect_uri !== redirect_uri) {
						throw new Error('Request JWT redirect_uri and authorization request redirect_uri search param do not match');
					}
	
					if(requestPayload.response_mode)
						response_mode = requestPayload.response_mode;
					
					if(requestPayload.nonce)
						nonce = requestPayload.nonce
				}
			}
			catch(error) {
				throw new Error(`Error decoding request search parameter: ${error}`);
			}
	

	
			// Finally, check if all required variables have been given
	
			if(response_type !== "vp_token" && response_type !== "id_token") {
				console.error(`Expected response_type = vp_token or id_token, got ${response_type}`);
				throw new Error('Invalid response type');
			}
	
			if(client_id === null) {
				throw new Error('Client ID not given');
			}
	
			if(redirect_uri === null) {
				throw new Error('Redirect URI not given');
			}
	
			if(scope !== "openid") {
				console.error(`Expected scope = openid, got ${scope}`);
				throw new Error('Invalid scope');
			}
	
			if(response_mode !== "direct_post") {
				console.error(`Expected response_mode = direct_post, got ${response_mode}`);
				throw new Error('Invalid response mode');
			}
	
			if(nonce === null) {
				throw new Error('Nonce not given');
			}
	
			// if(!presentation_definition) {
			// 	throw new Error('Presentation Definition not given');
			// }
	
			return {
				client_id,
				response_type,
				scope,
				redirect_uri,
				response_mode,
				nonce,
				state,
				request_uri
			}
	
		}

	private async tokenRequest(code: string, code_verifier: string): Promise<TokenResponseSchemaType> {
		const tokenEndpointURL = "https://api-conformance.ebsi.eu/conformance/v3/auth-mock/token";

		// Not adding authorization header
		// const basicAuthorizationB64 = Buffer.from(`${state.legalPerson.client_id}:${state.legalPerson.client_secret}`).toString("base64");
		const httpHeader = { 
			// "authorization": `Basic ${basicAuthorizationB64}`,
			"Content-Type": "application/x-www-form-urlencoded"
		};

		const data = new URLSearchParams();

		data.append('grant_type', 'authorization_code');
		data.append('code', code);
		data.append('code_verifier', code_verifier);


		data.append('client_id', this.walletDID);

		try {
			const httpResponse = await axios.post(tokenEndpointURL, data, { headers: httpHeader });
			const httpResponseBody = httpResponse.data as TokenResponseSchemaType;
			return httpResponseBody;
		}
		catch(err: any) {
			if (err.response) {
				console.error("HTTP response error body = ", err.response.data)
			}
			throw "Token Request failed"
		}

	}
}