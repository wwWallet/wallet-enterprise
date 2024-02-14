
import { CredentialIssuerMetadata, CredentialRequestBody, credentialRequestBodySchema } from "../../types/oid4vci";
import { SupportedCredentialProtocol } from "./SupportedCredentialProtocol";
import { Request, Response } from 'express';
import * as _ from 'lodash';
import { verifyProof } from "../../openid4vci/Proof/verifyProof";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { jwtDecrypt } from "jose";
import { keyPairPromise } from "../../openid4vci/utils/generateAccessToken";
import { CredentialSigner } from "../../services/interfaces";

export class CredentialIssuer {

	public credentialIssuerIdentifier: string = "";
	public supportedCredentials: SupportedCredentialProtocol[] = [];
	public authorizationServerURL: string = "";

	private credentialEndpointURL: string = "";

	private signer: CredentialSigner | undefined = undefined;

	private deferredCredentialEndpointURL?: string = undefined;
	private batchCredentialEndpointURL?: string = undefined;



	setCredentialIssuerIdentifier(id: string): this {
		this.credentialIssuerIdentifier = id;
		return this;
	}

	setSigner(signer: CredentialSigner): this {
		this.signer = signer;
		return this;
	}

	getCredentialSigner(): CredentialSigner {
		if (!this.signer)
			throw new Error("Signer is not defined");
		return this.signer;
	}

	setAuthorizationServerURL(authorizationServerURL: string): this {
		this.authorizationServerURL = authorizationServerURL;
		return this;
	}

	setCredentialEndpoint(endpoint: string): this {
		this.credentialEndpointURL = endpoint;
		return this;
	}

	setDeferredCredentialEndpoint(endpoint: string): this {
		this.deferredCredentialEndpointURL = endpoint;
		return this;
	}
	/**
	 * @throws
	 * @param supportedCredential 
	 * @returns 
	 */
	addSupportedCredential(supportedCredential: SupportedCredentialProtocol): this {
		const query = this.supportedCredentials.filter(sc => 
			sc.getFormat() == supportedCredential.getFormat() &&
			_.isEqual(sc.getTypes(), supportedCredential.getTypes())
		);

		if (query.length > 0)
			throw `Supported credential with id ${supportedCredential.getId()} cannot be added because there is supported credential with same (type, format) that already exists`;
		
		const queryForId = this.supportedCredentials.filter(sc =>
			sc.getId() == supportedCredential.getId()
		);
		if (queryForId.length > 0)
			throw `Supported credential with id ${supportedCredential.getId()} already exists`;

		this.supportedCredentials.push(supportedCredential);
		return this;
	}

	exportIssuerMetadata(): CredentialIssuerMetadata {
		return {
			credential_issuer: this.credentialIssuerIdentifier,
			authorization_server: this.authorizationServerURL,
			credential_endpoint: this.credentialEndpointURL,
			batch_credential_endpoint: this.batchCredentialEndpointURL,
			deferred_credential_endpoint: this.deferredCredentialEndpointURL,
			credentials_supported: this.supportedCredentials.map(sc => sc.exportCredentialSupportedObject())
		}
	}

	private async verifyAccessToken(req: Request, res: Response): Promise<{ userSession: AuthorizationServerState }> {
		console.log("Access token verification")
		if (!req.headers.authorization) {
			console.log("no authorization token found")
			res.status(500).send({})
			throw new Error("Invalid access token");
		}
		const access_token = req.headers.authorization.split(' ')[1];
		const { payload: { userSession }} = await jwtDecrypt(access_token, (await keyPairPromise).privateKey)
		// verify access_token, also validate the audience and the issuer (must be the authorization server)

		// const { userSession } = JSON.parse(base64url.decode(access_token.split('.')[1])) as { userSession: any };
		const deserializedSession = AuthorizationServerState.deserialize(userSession);
		return { userSession: deserializedSession };
	}

	async credentialRequestHandler(req: Request, res: Response): Promise<void> {
		let userSession: AuthorizationServerState | null = null;
		try {
			const result = await this.verifyAccessToken(req, res);
			userSession = result.userSession;
		}
		catch(err) {
			res.status(400).send(err);
			return;
		}

		const access_token = req.headers.authorization?.split(' ')[1] as string;
		try {
			const response = await this.returnSingleCredential(userSession, access_token, req.body as CredentialRequestBody)
			res.send(response);
		}
		catch(err) {
			console.log("Error: ", err);
			res.status(500).send({});
		}
	}

	async batchCredentialRequestHandler(req: Request, res: Response): Promise<void> {
		let userSession: AuthorizationServerState | null = null;
		try {
			const result = await this.verifyAccessToken(req, res);
			userSession = result.userSession;
		}
		catch(err) {
			res.status(400).send(err);
			return;
		}
		const access_token = req.headers.authorization?.split(' ')[1] as string;
		try {
			if (!userSession) {
				throw 'No user session exists';
			}
			const requests: CredentialRequestBody[] = req.body.credential_requests as CredentialRequestBody[];
			const responsePromises = [];
			for (const credReq of requests) {
				responsePromises.push(this.returnSingleCredential(userSession, access_token, credReq as CredentialRequestBody));
			}
			const responses = await Promise.all(responsePromises);
			res.send({ credential_responses: responses });
		}
		catch(err) {
			console.log("Error: ", err);
			res.status(500).send({});
		}
	}

	// async deferredCredentialRequestHandler(req: Request, res: Response): Promise<void> {
	// 	const acceptance_token = req.headers.authorization?.split(' ')[1] as string;
	// 	try {
	// 		const session = (await redisModule.getSessionByAcceptanceToken(acceptance_token)).unwrap();
	// 		const item = await credentialPoolService.getFromReadyCredentialsPoolDeferred(acceptance_token);
	// 		if (!item) {
	// 			console.log("Error: No credential to be returned");
	// 			res.status(500).send({});
	// 			return;
	// 		}
	// 		const { format, credential } = await item.supportedCredential.generateCredentialResponse(session, session.authorizationReqParams?.client_id as string);
	// 		res.send({ format, credential });
	// 	}
	// 	catch(err) {
	// 		console.log("Error: ", err);
	// 		res.status(500).send({});
	// 	}
	// }

	/**
	 * @throws
	 * @param userSession 
	 * @param credentialRequest 
	 * @returns 
	 */
	private async returnSingleCredential(userSession: AuthorizationServerState, _access_token: string, credentialRequest: CredentialRequestBody): Promise<{ acceptance_token?: string, credential?: any, format?: string }> {
		console.log("Credential request = ", credentialRequest)
		// incorrect credential issuer
		if (userSession.credential_issuer_identifier !== this.credentialIssuerIdentifier) {
			throw new Error('Invalid credential issuer');
		}
		
		let body: CredentialRequestBody;
		try {
			body = credentialRequestBodySchema.parse(credentialRequest);
		}
		catch(e) {
			console.log("invalid request body schema");
			throw 'Invalid request body'
		}
	
		// check proof
		const proof = body.proof;
		if (!proof) {
			throw new Error('no proof found')
		}
	
	
		// const associatedAuthorizationDetail = userSession.authorization_details?.filter(ad => 
		// 	ad.format == credentialRequest.format &&
		// 	_.isEqual(ad.types, credentialRequest.types))[0];
		
		// if (!associatedAuthorizationDetail?.locations ||
		// 	!Array.isArray(associatedAuthorizationDetail.locations) ||
		// 	associatedAuthorizationDetail.locations.length != 1) {
			
		// 	throw new Error("No location is given or invalid location on Authorization Details");
		// }
		// const credentialIssuerIdentifier = associatedAuthorizationDetail.locations[0];
		// WARNING: temporarily only the first credential is selected
		// After changing the OpenID4VCI spec, this endpoint must be changed.
		// const credentialIssuerIdentifier = userSession.categorizedRawCredentials
		// 	.filter(crc => userSession?.selectedCredentialIdList && crc.credential_id == userSession?.selectedCredentialIdList[0])[0].credentialIssuerIdentifier;
		// const authzDetails: AuthorizationDetail[] = JSON.parse(req.access_token_data.authzRequestData.authorizationReqParams.authorization_details);
		const { did } = await verifyProof(proof, userSession);
	
	
		if (!userSession.authorization_details) {
			throw new Error('No authorization details found');
		}
		const matched = userSession.authorization_details.filter((ad) => ad.format === body.format && _.isEqual(ad.types, body.types));
		if (matched.length == 0) { // this access token is not authorized to access this credential (format, types)
			throw new Error("Client not authorized to access this (types, format)")
		}
	
	

		let resolvedSupportedCredential = this.supportedCredentials
			.filter(sc => 
				sc.getFormat() == body.format && 
				_.isEqual(sc.getTypes(), body.types)
			)[0];

		if (!resolvedSupportedCredential) {
			throw new Error("Credential could not be resolved");
		}

		try {
			return await resolvedSupportedCredential.generateCredentialResponse(userSession, did);
		}
		catch(e) {
			throw new Error("Credential could not be returned. Error: " + e);
		}
	}


	async deferredCredentialRequestHandler(req: Request, res: Response) {
		console.log("Body = ", req.body);
		res.send({});
	}

	async getProfile(req: Request, res: Response) {
		
		const authorization_server_state = AuthorizationServerState.deserialize(req.body.authorization_server_state);
		// incorrect credential issuer
		if (authorization_server_state.credential_issuer_identifier !== this.credentialIssuerIdentifier) {
			return res.send({});
		}
		const types = req.body.types;
		const authorizationDetails = authorization_server_state.authorization_details;
		console.log("Authorization details = ", authorization_server_state.authorization_details)
		if (!authorizationDetails) {
			return res.status(400).send({ err: "Authorization details not provided" });
		}


		let supportedCredential: SupportedCredentialProtocol | null = null;
		for (const sc of this.supportedCredentials) {
			for (const ad of authorizationDetails) {
				if (sc.getFormat() == ad.format &&  _.isEqual(sc.getTypes(), ad.types) && _.isEqual(ad.types, types)) {
					supportedCredential = sc;
					break;
				}
			}
			if (supportedCredential)
				break;
		}

		if (supportedCredential) {
			const result = await supportedCredential.getProfile(authorization_server_state);
			return res.send({ credential_view: result });
		}
		else {
			return res.send({})
		}
	}



}







