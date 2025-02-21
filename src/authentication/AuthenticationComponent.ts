import { NextFunction, Request, Response } from "express";


export class AuthenticationComponent {
	constructor(public identifier: string, public protectedEndpoint: string) { }

	async authenticate(req: Request, _res: Response, next: NextFunction): Promise<any> {
		const confId = req.authorizationServerState?.credential_configuration_ids ? req.authorizationServerState?.credential_configuration_ids[0] : null;
		console.log("Authentication Component Identifier = ", this.identifier);
		console.log("Comparison = ", this.identifier.startsWith(confId + "-"));
		if (confId && this.identifier.startsWith(confId + "-")) {
			return next();
		}
		throw new Error("Not for this configuration id");
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