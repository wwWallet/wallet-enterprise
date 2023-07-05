import axios from "axios";
import * as randomstring from 'randomstring';
import * as crypto from 'crypto';
import base64url from "base64url";
import { CredentialIssuerMetadata } from "../types/oid4vci";

export async function generateCodeChallengeFromVerifier(v: any) {
	const base64Digest = crypto
		.createHash("sha256")
		.update(v)
		.digest("base64");
	console.log(base64Digest); // +PCBxoCJMdDloUVl1ctjvA6VNbY6fTg1P7PNhymbydM=

	return base64url.fromBase64(base64Digest);
}

export function generateCodeVerifier() {
	return randomstring.generate(128);
}

export function getIssuerMetadataUrl(issuerUrl: string) { return `${issuerUrl}/.well-known/openid-credential-issuer`; }

/**
 * Can use caching to reduce latency of the metadata retrieval
 * @param issuerUrl 
 * @returns 
 */
export async function getIssuerMetadata(issuerUrl: string): Promise<CredentialIssuerMetadata | null> {
	const issuerMetadataURL = getIssuerMetadataUrl(issuerUrl);
	console.log("issuer metadata url = ", issuerMetadataURL)
	const fetchIssuerMetadataRes = await axios.get(issuerMetadataURL).catch(e => {
		console.log('failed to fetch issuer metadata: ', e);
	})

	if (!fetchIssuerMetadataRes) {
		return null
	}
	const issuerMetadata: CredentialIssuerMetadata = fetchIssuerMetadataRes.data;
	return issuerMetadata;
}