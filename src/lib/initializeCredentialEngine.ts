import { HttpClient, MsoMdocParser, MsoMdocVerifier, ParsingEngine, PublicKeyResolverEngine, SDJWTVCParser, SDJWTVCVerifier } from 'core';
import { config } from '../../config';
import axios, { AxiosRequestHeaders } from 'axios';
import { webcrypto } from "node:crypto";
import { OpenID4VCICredentialRendering } from 'core/dist/functions/openID4VCICredentialRendering';
import { CredentialRenderingService } from 'core/dist/rendering';

export function initializeCredentialEngine() {
	console.log("Initializing credential engine...")
	const httpClient: HttpClient = {
		async get(url, headers) {
			return axios.get(url, { headers: headers as AxiosRequestHeaders }).then((res) => (res?.data ? {...res.data} : {})).catch((err) => (err?.response?.data ? {...err.response.data} : { }));
		},
		async post(url, data, headers) {
			return axios.post(url, data, { headers: headers as AxiosRequestHeaders }).then((res) => (res?.data ? {...res.data} : {})).catch((err) => (err?.response?.data ? {...err.response.data} : { }));
		},
	}
	
	const ctx = {
		// @ts-ignore
		clockTolerance: config.clockTolerance ?? 60,
		subtle: webcrypto.subtle as SubtleCrypto,
		lang: 'en-US',
		trustedCertificates: config.trustedRootCertificates,
	};
	const credentialParsingEngine = ParsingEngine();
	credentialParsingEngine.register(SDJWTVCParser({ context: ctx, httpClient: httpClient }));
	console.log("Registered SDJWTVCParser...");
	credentialParsingEngine.register(MsoMdocParser({ context: ctx, httpClient: httpClient }));
	console.log("Registered MsoMdocParser...");

	const pkResolverEngine = PublicKeyResolverEngine();
	const openid4vcRendering = OpenID4VCICredentialRendering({ httpClient });
	const credentialRendering = CredentialRenderingService();
	return {
		credentialParsingEngine,
		msoMdocVerifier: MsoMdocVerifier({ context: ctx, pkResolverEngine: pkResolverEngine }),
		sdJwtVerifier: SDJWTVCVerifier({ context: ctx, pkResolverEngine: pkResolverEngine }),
		openid4vcRendering,
		credentialRendering,
	};
}
