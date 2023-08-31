import { NextFunction, Request, Response } from "express";
import { AuthorizationDetailsSchemaType } from "../types/oid4vci";
import { appContainer } from "../services/inversify.config";
import { CredentialIssuersConfigurationService } from "../configuration/CredentialIssuersConfigurationService";



export class AuthenticationComponent {
	constructor(public identifier: string, public protectedEndpoint: string) { }

	async authenticate(req: Request, _res: Response, next: NextFunction): Promise<any> {
		const authorizationDetails = req.authorizationServerState.authorization_details;
		if (!authorizationDetails) {
			throw new Error("No authorization details where found")
		}

		if (!this.isRequired(authorizationDetails)) {
			throw new Error("Authentication component required");
		}
		return next();
	}

	private isRequired(authorizationDetails: AuthorizationDetailsSchemaType): boolean {
		for (const ad of authorizationDetails) {
			if (ad.locations) {
				for (const issuerId of ad.locations) {
					const issuer = appContainer.resolve(CredentialIssuersConfigurationService)
						.registeredCredentialIssuerRepository()
						.getCredentialIssuer(issuerId);
					if (issuer) {
						for (const sc of issuer.supportedCredentials) {
							const compIdList = sc.getAuthenticationComponentIds();
							if (compIdList.includes(this.identifier)) return true;
						}
					}
				}
			}
			else { // if no location specified, then it must pass from this authentication component
				return true
			}
		}
		return false;
	}
}

export type AuthenticationChain = {
	components: AuthenticationComponent[];
}

export class AuthenticationChainBuilder {

	constructor(private components: Array<AuthenticationComponent> = []) { }

	addAuthenticationComponent(comp: AuthenticationComponent): this {
		this.components.push(comp);
		return this;
	}

	build(): AuthenticationChain {
		return { components: this.components };
	}
}