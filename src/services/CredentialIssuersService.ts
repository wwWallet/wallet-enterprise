import { inject, injectable } from "inversify";
import 'reflect-metadata';
import { TYPES } from "./types";
import { Application } from "express";
import { CredentialIssuersRepository } from "../lib/CredentialIssuersRepository";
import { CredentialIssuersConfiguration } from "./interfaces";
import { authorizationServerMetadataConfiguration } from "../authorizationServiceConfiguration";

@injectable()
export class CredentialIssuersService {

	private credentialIssuersRepository: CredentialIssuersRepository;

	constructor(
		@inject(TYPES.CredentialIssuersConfiguration) private credentialIssuersConfigurationService: CredentialIssuersConfiguration,
	) { 
		this.credentialIssuersRepository = this.credentialIssuersConfigurationService.registeredCredentialIssuerRepository();
	}

	public exposeAllIssuers(app: Application) {
		this.credentialIssuersRepository.getAllCredentialIssuers()
			.map((iss) => {
				const prefix = new URL(iss.credentialIssuerIdentifier).pathname != "/" 
					? new URL(iss.credentialIssuerIdentifier).pathname
					: "";
				app.get(`${prefix}/.well-known/openid-credential-issuer`, async (_req, res) => { 
					res.send({
						...authorizationServerMetadataConfiguration,
						...iss.exportIssuerMetadata()
					});
				});
				app.post(`${prefix}/openid4vci/credential`, async (req, res) => iss.credentialRequestHandler(req, res));
				app.post(`${prefix}/openid4vci/deferred`, async (req, res) => iss.deferredCredentialRequestHandler(req, res));

				app.post(`${prefix}/profile`, async (req, res) => iss.getProfile(req, res));
			})
	}
}