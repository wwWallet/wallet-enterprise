import * as randomstring from 'randomstring';
import * as crypto from 'crypto';
import base64url from "base64url";

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
