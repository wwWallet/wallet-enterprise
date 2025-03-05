import { HttpClient, MsoMdocParser, MsoMdocVerifier, ParsingEngine, PublicKeyResolverEngine, SDJWTVCParser, SDJWTVCVerifier } from 'core';
import { config } from '../../config';
import axios, { AxiosRequestHeaders } from 'axios';
import { webcrypto } from "node:crypto";

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
	console.log("Registered SDJWTVCVerifier...");

	console.log("Registered MsoMdocVerifier...");

	return {
		credentialParsingEngine,
		msoMdocVerifier: MsoMdocVerifier({ context: ctx, pkResolverEngine: pkResolverEngine }),
		sdJwtVerifier: SDJWTVCVerifier({ context: ctx, pkResolverEngine: pkResolverEngine })
	};
}
