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


var issuerX5C: string[] = [];
var issuerPrivateKeyPem = "";
var issuerCertPem = "";
if (config.appType == "ISSUER") {
	issuerX5C = JSON.parse(fs.readFileSync(path.join(__dirname, "../../../keys/x5c.json"), 'utf-8').toString()) as string[];
	issuerPrivateKeyPem = fs.readFileSync(path.join(__dirname, "../../../keys/pem.key"), 'utf-8').toString();
	issuerCertPem = fs.readFileSync(path.join(__dirname, "../../../keys/pem.crt"), 'utf-8').toString() as string;

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


	public configure(app: Application) {
		app.get('/verification/request-object', async (req, res) => { this.presentationsReceivingService.getSignedRequestObject({ req, res }) });

		app.post('/verification/direct_post', async (req, res) => { this.presentationsReceivingService.responseHandler({ req, res }) });

		if (config.appType == "ISSUER") {
			app.post('/openid4vci/as/par', async (req, res) => {
				this.authorizationServerService.authorizationRequestHandler({ req, res });
			});

			// @ts-ignore
			if (config.issuanceFlow?.firstPartyAppDynamicCredentialRequest?.presentationDefinitionId) {
				app.post('/openid4vci/authorize-challenge', async (req, res) => {
					this.authorizationServerService.authorizeChallengeRequestHandler({ req, res });
				});
			}

			app.get('/openid4vci/authorize', async (req, res) => {
				this.authorizationServerService.authorizationRequestHandler({ req, res });
			});

			app.post('/openid4vci/token', async (req, res) => {
				this.authorizationServerService.tokenRequestHandler({ req, res });
			});

			app.post('/openid4vci/credential', async (req, res) => {
				this.authorizationServerService.credentialRequestHandler({ req, res });
			})

			app.get('/.well-known/oauth-authorization-server', async (_req, res) => {
				return res.send({
					issuer: config.url,
					authorization_endpoint: config.url + '/openid4vci/authorize',
					// @ts-ignore
					authorization_challenge_endpoint: config.issuanceFlow?.firstPartyAppDynamicCredentialRequest?.presentationDefinitionId ? config.url + '/openid4vci/authorize-challenge' : undefined,
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
					dpop_signing_alg_values_supported: ["ES256"]
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
					credential_endpoint: config.url + "/openid4vci/credential",
					batch_credential_issuance: undefined,
					display: config.display,
					credential_configurations_supported: credential_configurations_supported,
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

			if (config.supportsdjwtvc === true) {
				app.get('/.well-known/jwt-vc-issuer', async (_req, res) => {
					return res.send({
						issuer: config.url,
					})
				});
			}
		}

	}
}