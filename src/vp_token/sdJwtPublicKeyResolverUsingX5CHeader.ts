import base64url from "base64url";
import { VerifiableCredentialFormat } from "wallet-common/dist/types";
import { IPublicKeyResolver } from "./IPublicKeyResolver";
import { importX509, JWTHeaderParameters, KeyLike } from "jose";
import { verifyCertificateChain } from "../util/verifyCertificateChain";
import { config } from "../../config";

export const sdJwtPublicKeyResolverUsingX5CHeader: IPublicKeyResolver = {
	async resolve(rawPresentation: string | object, format: string): Promise<{ publicKey: KeyLike, isTrusted: boolean } | { error: "UNABLE_TO_RESOLVE_PUBKEY" }> {
		if (format != VerifiableCredentialFormat.VC_SDJWT || typeof rawPresentation != 'string') {
			return { error: "UNABLE_TO_RESOLVE_PUBKEY" };
		}

		let isTrusted = false;
		const [h, , ] = rawPresentation.split('.');
		const header = JSON.parse(base64url.decode(h)) as JWTHeaderParameters;
		if (header['x5c'] && header['x5c'] instanceof Array && header['x5c'][0]) {
			const pemCerts = header['x5c'].map(cert => {
				const pemCert = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`;
				return pemCert;
			});

			// check if at least one root certificate verifies this credential
			const result: boolean[] = await Promise.all(config.trustedRootCertificates.map(async (rootCert: string) => {
				return verifyCertificateChain(rootCert, pemCerts);
			}));


			if (config.trustedRootCertificates.length != 0 && !result.includes(true)) {
				console.log("Chain is not trusted");
				isTrusted = false;
			}
			isTrusted = true;
			console.info("Chain is trusted");
			const cert = await importX509(pemCerts[0], header['alg'] as string);
			return { isTrusted: isTrusted, publicKey: cert };
		}
		return { error: "UNABLE_TO_RESOLVE_PUBKEY" };
	}
}
