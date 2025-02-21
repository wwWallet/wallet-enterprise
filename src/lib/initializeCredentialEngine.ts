import { HttpClient, ParsingEngine, PublicKeyResolverEngine, SDJWTVCParser, SDJWTVCVerifier, VerifyingEngine } from 'core';
import { config } from '../../config';
import axios, { AxiosRequestHeaders } from 'axios';
import { webcrypto } from "node:crypto";

export function initializeCredentialEngine() {

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
		trustedCertificates: [],
	};
	const credentialParsingEngine = ParsingEngine();
	credentialParsingEngine.register(SDJWTVCParser({ context: ctx, httpClient: httpClient }));

	const pkResolverEngine = PublicKeyResolverEngine();
	const verifyingEngine = VerifyingEngine();
	verifyingEngine.register(SDJWTVCVerifier({ context: ctx, pkResolverEngine: pkResolverEngine }));
	return { credentialParsingEngine, verifyingEngine };
}
