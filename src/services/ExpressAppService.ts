import { Application } from 'express';
import { inject, injectable } from 'inversify';
import 'reflect-metadata';
import { TYPES } from './types';
import { OpenidForCredentialIssuingAuthorizationServerInterface } from './interfaces';
import { OpenidForPresentationsReceivingService } from './OpenidForPresentationReceivingService';
import { SKIP_CONSENT } from '../configuration/consent/consent.config';
import { CONSENT_ENTRYPOINT } from '../authorization/constants';
import config from '../../config';
import { CredentialIssuersService } from './CredentialIssuersService';
import { AuthorizationServerState } from '../entities/AuthorizationServerState.entity';
import AppDataSource from '../AppDataSource';
import { Repository } from 'typeorm';
import { ApplicationModeType, applicationMode } from '../configuration/applicationMode';
import { clearState } from '../middlewares/authorizationServerState.middleware';

@injectable()
export class ExpressAppService {

	
	private authorizationServerStateRepository: Repository<AuthorizationServerState> = AppDataSource.getRepository(AuthorizationServerState);


	constructor(
		@inject(TYPES.OpenidForCredentialIssuingAuthorizationServerService) private authorizationServerService: OpenidForCredentialIssuingAuthorizationServerInterface,
		@inject(TYPES.OpenidForPresentationsReceivingService) private presentationsReceivingService: OpenidForPresentationsReceivingService,
		@inject(TYPES.CredentialIssuersService) private credentialIssuersService: CredentialIssuersService
	) { }


	public configure(app: Application) {
		// exposed in any mode
		app.post('/verification/direct_post', this.directPostEndpoint());
		app.get('/verification/definition', async (req, res) => { this.presentationsReceivingService.getPresentationDefinitionHandler(req, res); });
		
		if (applicationMode == ApplicationModeType.VERIFIER || applicationMode == ApplicationModeType.ISSUER_AND_VERIFIER) {
			app.get('/verification/authorize', async (req, res) => {
				await clearState(res);
				this.presentationsReceivingService.authorizationRequestHandler(req, res, undefined);
			});
		}

		if (applicationMode == ApplicationModeType.ISSUER || applicationMode == ApplicationModeType.ISSUER_AND_VERIFIER) {
			app.get('/openid4vci/authorize', async (req, res) => {
				this.authorizationServerService.authorizationRequestHandler(req, res);
			});
			app.post('/openid4vci/token', async (req, res) => {
				this.authorizationServerService.tokenRequestHandler(req, res);
			});

			this.credentialIssuersService.exposeAllIssuers(app);
		}
	}

	private directPostEndpoint() {
		return async (req: any, res: any) => {
			let redirected = false;
			(res.redirect as any) = (url: string): void => {
				redirected = true;
				res.statusCode = 302;
				res.setHeader("Location", url);
				// Perform the actual redirect
				res.end();
			};

			//@ts-ignore
			(res.send as any) = (payload: string): void => {
				redirected = true;
				res.status(200);
				res.end();
				// Perform the actual redirect
			};
		
			
			let authorizationServerStateId;
			let verifier_state_id;
			try {
				const { bindedUserSessionId, verifierStateId } = await this.presentationsReceivingService.responseHandler(req, res);
				authorizationServerStateId = bindedUserSessionId;
				verifier_state_id = verifierStateId;
			}
			catch(e) {
				console.error(e);
				return;
			}
		
		
			if (redirected) {
				console.log("Already redirected")
				return;
			}
			
			if (SKIP_CONSENT) {
				try {
					if (!authorizationServerStateId) {
						const msg = {
							error: "No binded authorization request was found",
							error_description: "On /direct_post endpoint, the authorization request cannot be resolved"
						};
						console.error(msg);
						res.status(400).send(msg);
						return;
					}
					try {
						const state = await this.authorizationServerStateRepository.createQueryBuilder("state")
							.where("id = :id", { id: authorizationServerStateId })
							.getOne();
						if (state && state.authorization_details) {
							await this.authorizationServerService.sendAuthorizationResponse(req, res, state.id)
						}
						else {
							await this.presentationsReceivingService.sendAuthorizationResponse(req, res, verifier_state_id);
						}
					}
					catch(e) {
						const msg = {
							error: "Failed sendAuthorizationResponse()",
							error_description: String(e)
						};
						console.error(msg);
						res.status(400).send(msg);
						return;
					}
					return;
				}
				catch(err) {
					const msg = { error: String(err) };
					console.error(msg);
					res.status(400).send(msg);
					return;
				}
		
			}
			else { // redirect to entry point for user interaction
				res.redirect(config.url + CONSENT_ENTRYPOINT)
				return;
			}
		}
	}
}