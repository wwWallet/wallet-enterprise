import { base64url, importJWK, jwtVerify } from "jose";
import z from 'zod';
import { ProofType } from "../../types/oid4vci";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { appContainer } from "../../services/inversify.config";
import { TYPES } from "../../services/types";
import { DidKeyResolverServiceInterface } from "../../services/interfaces";

const proofHeaderSchema = z.object({
	kid: z.string(),
	alg: z.string(),
})

const proofBodySchema = z.object({
	iss: z.string().optional(),
	did: z.string().optional(), // fallback for "iss"
	aud: z.string(),
	iat: z.coerce.date(),
	nonce: z.string().optional(),
	c_nonce: z.string().optional() // fallback for 'nonce'
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

	const holderDID: string | undefined = proofHeader.kid; // did of the Holder
	if (!holderDID) {
		throw new Error("Holder DID cannot be derived from proof")
	}

	const publicKeyJwk = await appContainer.get<DidKeyResolverServiceInterface>(TYPES.DidKeyResolverService).getPublicKeyJwk(holderDID);

	// c nonce check and proof signature
	const holderPublicKey = await importJWK(publicKeyJwk, proofHeader.alg);
	try {
		// check for audience (must be issuer url)
		const { payload } = await jwtVerify(proof.jwt, holderPublicKey, {
			clockTolerance: '15 minutes'
		});
		proofBodySchema.parse(payload)

		if (payload["nonce"] !== session.c_nonce && payload["c_nonce"] !== session.c_nonce) { // use c_nonce attribute as a fallback for nonce
			throw new Error("INVALID C_NONCE");
		}
	}
	catch (e) {
		console.log("Error = ", e)
		throw new Error("Error during the verification of proof");
	}
	return { did: holderDID };
}