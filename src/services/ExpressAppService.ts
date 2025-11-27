import { Application } from 'express';
import { inject, injectable } from 'inversify';
import 'reflect-metadata';
import { TYPES } from './types';
import { CredentialConfigurationRegistry, OpenidForCredentialIssuingAuthorizationServerInterface } from './interfaces';
import { OpenidForPresentationsReceivingService } from './OpenidForPresentationReceivingService';
import { config } from '../../config';
import { importX509, SignJWT } from 'jose';
import { importPrivateKeyPem } from '../lib/importPrivateKeyPem';
import fs from 'fs';
import path from 'path';
import * as IssuerSigner from '../configuration/issuerSigner';
import { credentialConfigurationRegistryServiceEmitter } from './CredentialConfigurationRegistryService';
import { pemToBase64 } from '../util/pemToBase64';

var issuerX5C: string[] = [];
var issuerPrivateKeyPem = "";
var issuerCertPem = "";
var rootCaBase64DER = "";
if (config.appType == "ISSUER") {
	const caCertPem = fs.readFileSync(path.join(__dirname, "../../../keys/ca.crt"), 'utf-8').toString() as string;
	issuerPrivateKeyPem = fs.readFileSync(path.join(__dirname, "../../../keys/pem.key"), 'utf-8').toString();
	issuerCertPem = fs.readFileSync(path.join(__dirname, "../../../keys/pem.crt"), 'utf-8').toString() as string;
	issuerX5C = [
		pemToBase64(issuerCertPem),
		pemToBase64(caCertPem)
	];

	rootCaBase64DER = fs.readFileSync(path.join(__dirname, "../../../keys/ca.crt"), 'utf-8').toString() as string;
	rootCaBase64DER = rootCaBase64DER.replace(/-----BEGIN CERTIFICATE-----/g, '')
		.replace(/-----END CERTIFICATE-----/g, '')
		.replace(/\s+/g, '');

	importPrivateKeyPem(issuerPrivateKeyPem, 'ES256') // attempt to import the key
	importX509(issuerCertPem, 'ES256'); // attempt to import the public key

}


@injectable()
export class ExpressAppService {



	constructor(
		@inject(TYPES.OpenidForCredentialIssuingAuthorizationServerService) private authorizationServerService: OpenidForCredentialIssuingAuthorizationServerInterface,
		@inject(TYPES.OpenidForPresentationsReceivingService) private presentationsReceivingService: OpenidForPresentationsReceivingService,
		@inject(TYPES.CredentialConfigurationRegistryService) private credentialConfigurationRegistryService: CredentialConfigurationRegistry,
	) { }


	public async configure(app: Application): Promise<void> {
		app.get('/verification/request-object', async (req, res) => { this.presentationsReceivingService.getSignedRequestObject({ req, res }) });

		app.post('/verification/direct_post', async (req, res) => { this.presentationsReceivingService.responseHandler({ req, res }) });

		if (config.appType == "ISSUER") {
			app.post('/openid4vci/as/par', async (req, res) => {
				this.authorizationServerService.authorizationRequestHandler({ req, res });
			});

			// @ts-ignore
			if (config.issuanceFlow?.firstPartyAppDynamicCredentialRequest?.presentationRequestId) {
				app.post('/openid4vci/authorize-challenge', async (req, res) => {
					this.authorizationServerService.authorizeChallengeRequestHandler({ req, res });
				});
			}

			app.get('/openid4vci/authorize', async (req, res) => {
				this.authorizationServerService.authorizationRequestHandler({ req, res });
			});

			app.post('/openid4vci/nonce', async (req, res) => {
				this.authorizationServerService.nonceRequestHandler({ req, res });
			});
			app.post('/openid4vci/token', async (req, res) => {
				this.authorizationServerService.tokenRequestHandler({ req, res });
			});

			app.post('/openid4vci/credential', async (req, res) => {
				this.authorizationServerService.credentialRequestHandler({ req, res });
			})

			app.post('/openid4vci/credential/deferred', async (req, res) => {
				this.authorizationServerService.credentialRequestHandler({ req, res });
			})

			// @ts-ignore
			if (config.appType == "ISSUER" && IssuerSigner.issuerSigner) {
				app.get('/.well-known/jwks', async (_req, res) => {
					// @ts-ignore
					const { jwk } = await IssuerSigner.issuerSigner.getPublicKeyJwk();
					return res.send({
						keys: [
							{
								...jwk,
								use: "sig",
							}
						]
					})
				})

				app.get('/.well-known/jwt-vc-issuer', async (_req, res) => {
					// @ts-ignore
					const { jwk } = await IssuerSigner.issuerSigner.getPublicKeyJwk();
					return res.send({
						issuer: config.url,
						jwks: {
							keys: [
								{
									...jwk,
									use: "sig",
								}
							]
						}
					})
				})
			}
			app.get('/.well-known/oauth-authorization-server', async (_req, res) => {
				const x = await Promise.all(this.credentialConfigurationRegistryService.getAllRegisteredCredentialConfigurations());

				return res.send({
					issuer: config.url,
					authorization_endpoint: config.url + '/openid4vci/authorize',
					// @ts-ignore
					authorization_challenge_endpoint: config.issuanceFlow?.firstPartyAppDynamicCredentialRequest?.presentationRequestId ? config.url + '/openid4vci/authorize-challenge' : undefined,
					token_endpoint: config.url + '/openid4vci/token',
					pushed_authorization_request_endpoint: config.url + '/openid4vci/as/par',
					require_pushed_authorization_requests: true,
					token_endpoint_auth_methods_supported: [
						"none"
					],
					response_types_supported: [
						"code"
					],
					code_challenge_methods_supported: [
						"S256"
					],
					dpop_signing_alg_values_supported: ["ES256"],
					grant_types_supported: [
						"authorization_code",
						"refresh_token",
					],
					jwks_uri: config.url + '/.well-known/jwks',
					scopes_supported: x.map((cred) => cred.getScope())
				})
			});

			app.get('/mdoc-iacas', async (_req, res) => {
				res.set('Cache-Control', 'public, max-age=86400');
				return res.json({
					iacas: [
						{
							certificate: rootCaBase64DER
						}
					]
				})
			});

			app.get('/.well-known/openid-credential-issuer', async (_req, res) => {
				const x = await Promise.all(this.credentialConfigurationRegistryService.getAllRegisteredCredentialConfigurations());
				const credential_configurations_supported: { [x: string]: any } = {};
				x.map((credentialConfiguration) => {
					credential_configurations_supported[credentialConfiguration.getId()] = credentialConfiguration.exportCredentialSupportedObject();
				})

				const metadata = {
					credential_issuer: config.url,
					nonce_endpoint: config.url + "/openid4vci/nonce",
					credential_endpoint: config.url + "/openid4vci/credential",
					deferred_credential_endpoint: config.url + "/openid4vci/credential/deferred",
					batch_credential_issuance: undefined,
					display: config.display,
					credential_configurations_supported: credential_configurations_supported,
					mdoc_iacas_uri: config.url + '/mdoc-iacas',
				};

				// @ts-ignore
				const batchSize = config.issuanceFlow?.batchCredentialIssuance?.batchSize;

				if (batchSize) {
					// @ts-ignore
					metadata.batch_credential_issuance = {
						batch_size: batchSize
					};
				}
				const key = await importPrivateKeyPem(issuerPrivateKeyPem, 'ES256');
				if (!key) {
					throw new Error("Could not import private key");
				}
				const signedMetadata = await new SignJWT(metadata)
					.setIssuedAt()
					.setIssuer(config.url)
					.setSubject(config.url)
					.setProtectedHeader({ typ: "JWT", alg: "ES256", x5c: issuerX5C })
					.sign(key);
				// @ts-ignore
				return res.send({ ...metadata, signed_metadata: signedMetadata });
			});

			const allTypeMetadataByVct = new Map<string, any>();
			const dynamicVctMap = new Map();

			await new Promise((resolve) => {
				credentialConfigurationRegistryServiceEmitter.on('initialized', () => {
					this.credentialConfigurationRegistryService.getAllRegisteredCredentialConfigurations().map((configuration) => {
						// @ts-ignore
						if (configuration?.metadata) {
							// @ts-ignore
							const metadata = configuration?.metadata();
							const metadataArray = Array.isArray(metadata) ? metadata : [metadata];

							metadataArray.forEach((item: any) => {
								try {
									allTypeMetadataByVct.set(item.vct, item);
									const newUrl = new URL(item.vct);
									let path = null;
									if ((newUrl.protocol === "http:" || newUrl.protocol === "https:")) {
										path = newUrl.pathname;

										console.log(`✅ Registering route: ${path}`);
										app.get(path, async (_req, res) => {
											return res.send({
												...item
											})
										});

									} else {
										dynamicVctMap.set(item.vct, item)
									}
								} catch (error) {
									console.error(`❌ Error processing item.vct (${item.vct}):`, error);
								}
							});
						}

					})

					console.log("✅ Registering route /type-metadata VCTs:", Array.from(dynamicVctMap.keys()));

					app.get('/type-metadata', async (req, res) => {
						const vct = req.query.vct;
						if (!dynamicVctMap.has(vct)) {
							return res.status(500).send({});
						}
						return res.send({
							...dynamicVctMap.get(vct)
						})
					});

					resolve(null);
				})

			})
			console.log("✅ Registering route /type-metadata/all VCTs:", Array.from(allTypeMetadataByVct.keys()));
			app.get('/type-metadata/all', async (_req, res) => {
				const all = Array.from(allTypeMetadataByVct.values());
				return res.send(all);
			});
		}
	}
}
