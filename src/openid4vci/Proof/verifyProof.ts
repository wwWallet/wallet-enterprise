import { JWK, base64url, importJWK, jwtVerify } from "jose";
import z from 'zod';
import { ProofType } from "../../types/oid4vci";
import * as ed25519 from '@transmute/did-key-ed25519';
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";

const proofHeaderSchema = z.object({
	kid: z.string(),
	alg: z.string(),
})

const proofBodySchema = z.object({
	iss: z.string(),
	aud: z.string(),
	iat: z.coerce.date(),
	nonce: z.string(),
})

type Proof = {
	proof_type: ProofType,
	jwt?: string;
}

type JwtProof = {
	proof_type: ProofType,
	jwt: string;
}

/**
 * 
 * @param proof 
 * @param session 
 * @returns 
 * @throws
 */
export async function verifyProof(proof: Proof, session: AuthorizationServerState): Promise<{ did: string }> {
	switch (proof.proof_type) {
	case ProofType.JWT:
		return verifyJwtProof(proof as JwtProof, session);
	default:
		throw `Proof type "${proof.proof_type}" not supported`;
	}
}

/**
 * @throws
 * @param proof 
 */
async function verifyJwtProof(proof: JwtProof, session: AuthorizationServerState): Promise<{ did: string }> {
	if (!proof.jwt) {
		console.log("holder pub key or proof jwt are not existent")
		throw "UNDEFINED_PROOF";
	}

	// check with zod
	const proofHeader = proofHeaderSchema.parse(JSON.parse(new TextDecoder().decode(base64url.decode(proof.jwt.split('.')[0]))));
	console.log("Proof header = ", proofHeader)
	console.log("Proof body = ", JSON.parse(new TextDecoder().decode(base64url.decode(proof.jwt.split('.')[1]))))

	const proofPayload = proofBodySchema.parse(JSON.parse(new TextDecoder().decode(base64url.decode(proof.jwt.split('.')[1]))));

	const holderDID: string = proofPayload.iss; // did of the Holder


	const {
		didDocument,
	} = await ed25519.resolve(
		holderDID,
		{ accept: 'application/did+json' }
	);

	// const thumbprint = await calculateJwkThumbprint(holderPublicKeyJwk, "sha256");
	// const subjectIdentifier: Buffer = Buffer.from(thumbprint, "base64");
	// const BYTE_LENGTH = 32; // for Natural Persons
	// const VERSION_ID = 2; // for Natural Persons
	// const bytesArray = new Uint8Array(1 + BYTE_LENGTH);
	// bytesArray.set([VERSION_ID]);
	// bytesArray.set(subjectIdentifier, 1);
	// const trueDID = "did:ebsi:" + base58btc.encode(bytesArray);
	// console.log("True DID = ", trueDID)
	// console.log("Holder did = ", holderDID)
	// if (trueDID !== holderDID) {
	// 	console.log("Wrong pub key");
	// 	throw "WRONG PUB KEY";
	// }
	const { publicKeyJwk } =  didDocument.verificationMethod[0] as { publicKeyJwk: JWK };

	console.log("Session = ", session)
	// c nonce check and proof signature
	const holderPublicKey = await importJWK(publicKeyJwk, proofHeader.alg);
	try {
		// check for audience (must be issuer url)
		const { payload } = await jwtVerify(proof.jwt, holderPublicKey);
		if (payload["nonce"] !== session.c_nonce) {
			throw new Error("INVALID C_NONCE");
		}
	}
	catch(e) {
		console.log("Error = ", e)
		throw new Error("Error during the verification of proof");
	}
	return { did: holderDID };
}