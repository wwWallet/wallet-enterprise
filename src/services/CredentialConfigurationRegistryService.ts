import { injectable } from "inversify";
import 'reflect-metadata';
import { CredentialConfigurationRegistry } from "./interfaces";
import { CredentialView } from "../authorization/types";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
import { SupportedCredentialProtocol } from "../lib/CredentialIssuerConfig/SupportedCredentialProtocol";
import { JWK } from "jose";
import EventEmitter from "node:events";


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
			const result = await conf.getProfile(authorizationServerState).catch((_err) => null);
			if (result != null) {
				return result;
			}
		}
		return null;
	}

	async getCredentialResponse(authorizationServerState: AuthorizationServerState, credentialRequest: any, holderPublicKeyToBind: JWK) {
		for (const conf of this.credentialConfigurations) {
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