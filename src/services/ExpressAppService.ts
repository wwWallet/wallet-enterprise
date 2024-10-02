import { Application } from 'express';
import { inject, injectable } from 'inversify';
import 'reflect-metadata';
import { TYPES } from './types';
import { CredentialConfigurationRegistry, OpenidForCredentialIssuingAuthorizationServerInterface } from './interfaces';
import { OpenidForPresentationsReceivingService } from './OpenidForPresentationReceivingService';
import { config } from '../../config';

@injectable()
export class ExpressAppService {

	

	constructor(
		@inject(TYPES.OpenidForCredentialIssuingAuthorizationServerService) private authorizationServerService: OpenidForCredentialIssuingAuthorizationServerInterface,
		@inject(TYPES.OpenidForPresentationsReceivingService) private presentationsReceivingService: OpenidForPresentationsReceivingService,
		@inject(TYPES.CredentialConfigurationRegistryService) private credentialConfigurationRegistryService: CredentialConfigurationRegistry,
	) { }


	public configure(app: Application) {
		app.get('/verification/request-object', async (req, res) => { this.presentationsReceivingService.getSignedRequestObject({req, res} )});

		app.post('/verification/direct_post', async (req, res) => { this.presentationsReceivingService.responseHandler({req, res}) });
		app.get('/verification/definition', async (req, res) => { this.presentationsReceivingService.getPresentationDefinitionHandler({req, res}); });
		

		app.get('/openid4vci/authorize', async (req, res) => {
			this.authorizationServerService.authorizationRequestHandler({req, res});
		});
		app.post('/openid4vci/as/par', async (req, res) => {
			this.authorizationServerService.authorizationRequestHandler({req, res});
		});
		app.post('/openid4vci/token', async (req, res) => {
			this.authorizationServerService.tokenRequestHandler({req, res});
		});

		app.post('/openid4vci/credential', async (req, res) => {
			this.authorizationServerService.credentialRequestHandler({req, res});
		})

		app.get('/.well-known/oauth-authorization-server', async (_req, res) => {
			return res.send({
				issuer: config.url,
				authorization_endpoint: config.url + '/openid4vci/authorize',
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
			return res.send({
				credential_issuer: config.url,
				credential_endpoint: config.url + "/openid4vci/credential",
				display: config.display,
				credential_configurations_supported: credential_configurations_supported,
			})
		});
	}
}