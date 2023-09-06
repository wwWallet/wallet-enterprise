import { NextFunction, Request, Response } from "express";


export class AuthenticationComponent {
	constructor(public identifier: string, public protectedEndpoint: string) { }

	async authenticate(_req: Request, _res: Response, next: NextFunction): Promise<any> {
		return next();
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