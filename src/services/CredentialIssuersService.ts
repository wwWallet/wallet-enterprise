import { inject, injectable } from "inversify";
import 'reflect-metadata';
import { TYPES } from "./types";
import { Application } from "express";
import { CredentialIssuersRepository } from "../lib/CredentialIssuersRepository";
import { CredentialIssuersConfiguration } from "./interfaces";
import { authorizationServerMetadataConfiguration } from "../authorizationServiceConfiguration";
import { CredentialIssuer } from "../lib/CredentialIssuerConfig/CredentialIssuer";

@injectable()
export class CredentialIssuersService {

	private credentialIssuersRepository: CredentialIssuersRepository;

	constructor(
		@inject(TYPES.CredentialIssuersConfiguration) private credentialIssuersConfigurationService: CredentialIssuersConfiguration,
	) { 
		this.credentialIssuersRepository = this.credentialIssuersConfigurationService.registeredCredentialIssuerRepository();
	}

	public getIssuerByIdentifier(credentialIssuerIdentifier: string): CredentialIssuer {
		const result = this.credentialIssuersRepository.getCredentialIssuer(credentialIssuerIdentifier);
		if (!result) {
			throw new Error("Credential issuer does not exist");
		}
		return result;
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