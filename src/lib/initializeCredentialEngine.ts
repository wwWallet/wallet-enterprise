import { MsoMdocParser, MsoMdocVerifier, ParsingEngine, PublicKeyResolverEngine, SDJWTVCParser, SDJWTVCVerifier } from 'core';
import { config } from '../../config';
import { webcrypto } from "node:crypto";
import { OpenID4VCICredentialRendering } from 'core/dist/functions/openID4VCICredentialRendering';
import { CredentialRenderingService } from 'core/dist/rendering';
import { defaultHttpClient } from 'core/dist/defaultHttpClient';

export function initializeCredentialEngine() {
	console.log("Initializing credential engine...")

	const ctx = {
		// @ts-ignore
		clockTolerance: config.clockTolerance ?? 60,
		subtle: webcrypto.subtle as SubtleCrypto,
		lang: 'en-US',
		trustedCertificates: config.trustedRootCertificates,
	};
	const credentialParsingEngine = ParsingEngine();
	credentialParsingEngine.register(SDJWTVCParser({ context: ctx, httpClient: defaultHttpClient }));
	console.log("Registered SDJWTVCParser...");
	credentialParsingEngine.register(MsoMdocParser({ context: ctx, httpClient: defaultHttpClient }));
	console.log("Registered MsoMdocParser...");

	const pkResolverEngine = PublicKeyResolverEngine();
	const openid4vcRendering = OpenID4VCICredentialRendering({ httpClient: defaultHttpClient });
	const credentialRendering = CredentialRenderingService();
	return {
		credentialParsingEngine,
		msoMdocVerifier: MsoMdocVerifier({ context: ctx, pkResolverEngine: pkResolverEngine }),
		sdJwtVerifier: SDJWTVCVerifier({ context: ctx, pkResolverEngine: pkResolverEngine }),
		openid4vcRendering,
		credentialRendering,
	};
}
