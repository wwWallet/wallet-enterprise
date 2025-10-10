import { JptDcParser, MsoMdocParser, MsoMdocVerifier, ParsingEngine, PublicKeyResolverEngine, SDJWTVCParser, SDJWTVCVerifier } from 'wallet-common';
import { config } from '../../config';
import { webcrypto } from "node:crypto";
import { OpenID4VCICredentialRendering } from 'wallet-common/dist/functions/openID4VCICredentialRendering';
import { CredentialRenderingService } from 'wallet-common/dist/rendering';
import { defaultHttpClient } from 'wallet-common/dist/defaultHttpClient';
import axios from 'axios';
import { JptDcVerifier } from 'wallet-common/dist/credential-verifiers/JptDcVerifier';
import { getBbsPublicKeyOrFail } from '../keys';

// @ts-ignore
const trustedCredentialIssuerIdentifiers = config.trustedIssuers as string[] | undefined;

export async function initializeCredentialEngine() {
	console.log("Initializing credential engine...")

	const ctx = {
		// @ts-ignore
		clockTolerance: config.clockTolerance ?? 60,
		subtle: webcrypto.subtle as SubtleCrypto,
		lang: 'en-US',
		trustedCertificates: [...config.trustedRootCertificates] as string[],
	};

	if (trustedCredentialIssuerIdentifiers) {
		const result = (await Promise.all(trustedCredentialIssuerIdentifiers.map(async (credentialIssuerIdentifier) =>
			axios.get(`${credentialIssuerIdentifier}/.well-known/openid-credential-issuer`)
				.then((res) => res.data)
				.catch((e) => { console.error(e); return null; })
		))).filter((r: any) => r !== null);

		const iacasResponses = (await Promise.all(result.map(async (metadata) => {
			if (metadata && metadata.mdoc_iacas_uri) {
				return axios.get(metadata.mdoc_iacas_uri).then((res) => res.data).catch((e) => { console.error(e); return null; })
			}
			return null;
		}))).filter((r: any) => r !== null);

		for (const iacaResponse of iacasResponses) {
			const pemCertificates = iacaResponse.iacas.map((cert: { certificate?: string }) =>
				cert.certificate ? `-----BEGIN CERTIFICATE-----\n${cert.certificate}\n-----END CERTIFICATE-----\n` : null
			)
			for (const pem of pemCertificates) {
				if (pem) {
					ctx.trustedCertificates.push(pem);
				}
			}
		}
	}

	const credentialParsingEngine = ParsingEngine();
	credentialParsingEngine.register(JptDcParser({ context: ctx, httpClient: defaultHttpClient }));
	console.log("Registered JptDcParser...");
	credentialParsingEngine.register(SDJWTVCParser({ context: ctx, httpClient: defaultHttpClient }));
	console.log("Registered SDJWTVCParser...");
	credentialParsingEngine.register(MsoMdocParser({ context: ctx, httpClient: defaultHttpClient }));
	console.log("Registered MsoMdocParser...");

	const pkResolverEngine = PublicKeyResolverEngine();
	const openid4vcRendering = OpenID4VCICredentialRendering({ httpClient: defaultHttpClient });
	const credentialRendering = CredentialRenderingService();
	const issuerBbsPublicKey = getBbsPublicKeyOrFail();
	const args = { context: ctx, pkResolverEngine: pkResolverEngine };
	return {
		credentialParsingEngine,
		msoMdocVerifier: MsoMdocVerifier(args),
		sdJwtVerifier: SDJWTVCVerifier({ ...args, httpClient: defaultHttpClient }),
		jptVerifier: JptDcVerifier({ ...args, httpClient: defaultHttpClient, issuerPublicKeys: [issuerBbsPublicKey] }),
		openid4vcRendering,
		credentialRendering,
	};
}
