import base64url from "base64url";
import { importJWK, jwtVerify } from "jose";
import crypto from 'node:crypto';




export async function calculateHash(text: string) {
	const encoder = new TextEncoder();
	const data = encoder.encode(text);
	const hashBuffer = await crypto.webcrypto.subtle.digest('SHA-256', data);
	const base64String = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
	const base64UrlString = base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	return base64UrlString;
}

export async function verifyKbJwt(vp_token: string, requirements: { aud?: string, nonce?: string }) {
	try {
		const sdJwt = vp_token.split('~').slice(0, -1).join('~') + '~';
		const kbJwt = vp_token.split('~')[vp_token.split('~').length - 1] as string;
	
		const jwtPayload = (JSON.parse(base64url.decode(sdJwt.split('.')[1])) as any);
	
		const { alg } = JSON.parse(base64url.decode(kbJwt.split('.')[0])) as { alg: string };
		const publicKey = await importJWK(jwtPayload.cnf.jwk, alg);
		const { sd_hash, nonce, aud } = JSON.parse(base64url.decode(kbJwt.split('.')[1])) as any;
		if (await calculateHash(sdJwt) != sd_hash) {
			throw new Error("Wrong sd_hash");
		}
		if (aud != requirements.aud) {
			throw new Error("Wrong aud");
		}
	
		if (nonce != requirements.nonce) {
			throw new Error("Wrong nonce");
		}
		await jwtVerify(kbJwt, publicKey);
		return true;
	}
	catch(err) {
		console.log("Error on verifyKbJwt()");
		console.log(err);
		return false;
	}

}

