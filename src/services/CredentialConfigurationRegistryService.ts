import { injectable } from "inversify";
import 'reflect-metadata';
import { CredentialConfigurationRegistry } from "./interfaces";
import { CredentialView } from "../authorization/types";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
import { SupportedCredentialProtocol } from "../lib/CredentialIssuerConfig/SupportedCredentialProtocol";
import { JWK } from "jose";
import EventEmitter from "node:events";
import { Request } from 'express';

class CredentialConfigurationRegistryServiceEmitter extends EventEmitter { }

export const credentialConfigurationRegistryServiceEmitter = new CredentialConfigurationRegistryServiceEmitter();

@injectable()
export class CredentialConfigurationRegistryService implements CredentialConfigurationRegistry {

	private credentialConfigurations: SupportedCredentialProtocol[] = [];

	constructor() { }

	getAllRegisteredCredentialConfigurations(): SupportedCredentialProtocol[] {
		return this.credentialConfigurations;
	}


	register(credentialConfiguration: SupportedCredentialProtocol): void {
		this.credentialConfigurations.push(credentialConfiguration);
		console.log("Registered credential configuration with id ", credentialConfiguration.getId());
	}

	async getCredentialView(authorizationServerState: AuthorizationServerState): Promise<CredentialView | null> {
		for (const conf of this.credentialConfigurations) {
			if (!authorizationServerState.scope?.split(' ').includes(conf.getScope())) {
				continue;
			}
			const result = await conf.getProfile(authorizationServerState).catch((_err) => null);
			if (result != null) {
				return result;
			}
		}
		return null;
	}

	async getCredentialResponse(authorizationServerState: AuthorizationServerState, credentialRequest: Request, holderPublicKeyToBind: JWK) {
		console.log("CRED REQ BODY = ", credentialRequest.body);
		console.log("Authorization server state before credential response: ", authorizationServerState);
		console.log("Authorized for scopes: ", authorizationServerState.scope);
		for (const conf of this.credentialConfigurations) {
			if (
				!credentialRequest.body.credential_configuration_id || // credential request body must include "credential_configuration_id" param
				!authorizationServerState.scope?.split(',').includes(conf.getScope()) || // filter out the non authorized scopes
				credentialRequest.body.credential_configuration_id !== conf.getId()) { // filter out if it not requested on this Credential Request
				continue;
			}
			const result = await conf.generateCredentialResponse(authorizationServerState, credentialRequest, holderPublicKeyToBind).catch((err) => {
				console.log(err)
				return null;
			});
			if (result != null) {
				return result;
			}
		}
		return null;
	}
}
