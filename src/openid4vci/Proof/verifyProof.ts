import { base64url, importJWK, jwtVerify } from "jose";
import z from 'zod';
import { ProofType } from "../../types/oid4vci";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { appContainer } from "../../services/inversify.config";
import { TYPES } from "../../services/types";
import { DidKeyResolverService } from "../../services/interfaces";

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


	const publicKeyJwk = await appContainer.get<DidKeyResolverService>(TYPES.DidKeyResolverService).getPublicKeyJwk(holderDID);
	
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