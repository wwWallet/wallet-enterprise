import { NextFunction, Request, Response } from "express";


export class AuthenticationComponent {
	constructor(public identifier: string, public protectedEndpoint: string) { }

	async authenticate(req: Request, _res: Response, next: NextFunction): Promise<any> {
		const scopeName = req.authorizationServerState?.scope ? req.authorizationServerState?.scope : null;
		console.log("Scope = ", scopeName)
		console.log("Authentication Component Identifier = ", this.identifier);
		console.log("Comparison = ", this.identifier.startsWith(scopeName + "-"));
		if (scopeName && this.identifier.startsWith(scopeName + "-")) {
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
