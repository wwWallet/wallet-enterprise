import { NextFunction, Request, Response } from "express";
import { redisModule } from "../../RedisModule";
import z from 'zod';
import * as _ from 'lodash';
import { verifyProof } from "../Proof/verifyProof";
import { UserSession } from "../../RedisModule";
import { ProofType, VerifiableCredentialFormat } from "../../types/oid4vci";
import { issuersConfigurations } from "../../configuration/IssuersConfiguration";

const credentialRequestBodySchema = z.object({
	format: z.nativeEnum(VerifiableCredentialFormat),
	types: z.array(z.string()),
	proof: z.object({
		proof_type: z.nativeEnum(ProofType),
		jwt: z.string()
	})
})

type CredentialRequestBody = z.infer<typeof credentialRequestBodySchema>;


async function verifyAccessToken(req: Request, res: Response, next: NextFunction) {
	console.log("Access token verification")
	if (!req.headers.authorization) {
		console.log("no authorization token found")
		res.status(500).send({})
		return;
	}
	const access_token = req.headers.authorization.split(' ')[1];

	const sessionRes = await redisModule.getSessionByAccessToken(access_token);
	if (sessionRes.err) {
		switch (sessionRes.val) {
		case "KEY_NOT_FOUND":
			console.log("Key not found")
			res.status(401).send({});
			return;
		case "REDIS_ERR":

			console.log('Redis err');
			res.status(500).send({});
			return;
		}
	}
	req.userSession = sessionRes.unwrap();
	next();
}

async function credentialEndpoint(req: Request, res: Response) {
	console.log('Hello')
	try {
		if (!req.userSession) {
			throw 'No user session exists';
		}
		const response = await returnSingleCredential(req.userSession, req.body as CredentialRequestBody)
		res.send(response);
	}
	catch(err) {
		console.log("Error: ", err);
		res.status(500).send({});
	}
}


async function batchCredentialEndpoint(req: Request, res: Response) {
	try {
		if (!req.userSession) {
			throw 'No user session exists';
		}
		const requests: CredentialRequestBody[] = req.body.credential_requests as CredentialRequestBody[];
		const responsePromises = [];
		for (const credReq of requests) {
			responsePromises.push(returnSingleCredential(req.userSession, credReq as CredentialRequestBody));
		}
		const responses = await Promise.all(responsePromises);
		res.send({ credential_responses: responses });
	}
	catch(err) {
		console.log("Error: ", err);
		res.status(500).send({});
	}
}




async function returnSingleCredential(userSession: UserSession, credentialRequest: CredentialRequestBody) {
	console.log("Credential request = ", credentialRequest)
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
		throw 'no proof found'
	}


	const associatedAuthorizationDetail = userSession.authorizationDetails?.filter(ad => 
		ad.format == credentialRequest.format &&
		_.isEqual(ad.types, credentialRequest.types))[0];
	
	if (!associatedAuthorizationDetail?.locations ||
		!Array.isArray(associatedAuthorizationDetail.locations) ||
		associatedAuthorizationDetail.locations.length != 1) {
		
		throw "No location is given or invalid location on Authorization Details"
	}
	const credentialIssuerIdentifier = associatedAuthorizationDetail.locations[0];
	// WARNING: temporarily only the first credential is selected
	// After changing the OpenID4VCI spec, this endpoint must be changed.
	console.log("Raw creds = ", userSession.categorizedRawCredentials)
	// const credentialIssuerIdentifier = userSession.categorizedRawCredentials
	// 	.filter(crc => userSession?.selectedCredentialIdList && crc.credential_id == userSession?.selectedCredentialIdList[0])[0].credentialIssuerIdentifier;
	console.log("Credential issuer identifier = ", credentialIssuerIdentifier)
	// const authzDetails: AuthorizationDetail[] = JSON.parse(req.access_token_data.authzRequestData.authorizationReqParams.authorization_details);
	const { did } = await verifyProof(proof, userSession);


	if (!userSession.authorizationDetails) {
		throw 'No authorization details found'
	}
	const matched = userSession.authorizationDetails.filter((ad) => ad.format === body.format && _.isEqual(ad.types, body.types));
	if (matched.length == 0) { // this access token is not authorized to access this credential (format, types)
		throw "No authorized for this (types, format)"
	}


	const issuer = issuersConfigurations.get(credentialIssuerIdentifier);
	console.log("Issuer = ", issuer)
	if (!issuer) {
		throw "Issuer not found"
	}

	const supportedCredential = issuer.supportedCredentials
		.filter(sc => 
			sc.getFormat() == body.format && 
			_.isEqual(sc.getTypes(), body.types)
		)[0];
	

	const { format, credential } = await supportedCredential.signCredential(userSession, did);
	const credentialResponse = { format: format, credential: credential };
	console.log("Credential response = ", credentialResponse)
	return credentialResponse;
}


export {
	verifyAccessToken,
	credentialEndpoint,
	batchCredentialEndpoint
}