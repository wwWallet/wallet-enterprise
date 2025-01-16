import { NextFunction, Request, Response } from "express";
import { ParamsDictionary } from "express-serve-static-core";
import { ParsedQs } from "qs";
import { AuthenticationComponent } from "../AuthenticationComponent";
import AppDataSource from "../../AppDataSource";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import locale from "../../configuration/locale";
import { UserAuthenticationMethod } from "../../types/UserAuthenticationMethod.enum";


export class GenericAuthenticationMethodSelectionComponent extends AuthenticationComponent {

	constructor(
		override identifier: string,
		override protectedEndpoint: string,
		private availableAuthenticationMethods: { code: UserAuthenticationMethod, description: string }[],
	) { super(identifier, protectedEndpoint) }

	public override async authenticate(
		req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
		res: Response<any, Record<string, any>>,
		next: NextFunction) {

		return super.authenticate(req, res, async () => {
			if (await this.hasSelectedAuthenticationMethod(req)) {
				return next();
			}

			if (req.method == "POST") {
				return this.handleAuthenticationMethodSelection(req, res);
			}

			return this.renderAuthenticationMethodSelection(req, res);
		})
			.catch(() => {
				return next();
			});
	}



	private async hasSelectedAuthenticationMethod(req: Request): Promise<boolean> {
		if (!req.session.authenticationChain?.authenticationMethodSelectionComponent?.authentication_method) {
			return false;
		}
		return true;
	}

	private async handleAuthenticationMethodSelection(req: Request, res: Response): Promise<any> {
		const { auth_method } = req.body;
		if (auth_method) {
			if (!auth_method || (
				auth_method != UserAuthenticationMethod.SSO &&
				auth_method != UserAuthenticationMethod.VID_AUTH)) {
				return this.renderAuthenticationMethodSelection(req, res);
			}

			req.session.authenticationChain.authenticationMethodSelectionComponent = {
				authentication_method: auth_method
			};

			req.authorizationServerState.authenticationMethod = auth_method;

			await AppDataSource.getRepository(AuthorizationServerState).save(req.authorizationServerState);
			return res.redirect(this.protectedEndpoint);
		}
		else {
			return this.renderAuthenticationMethodSelection(req, res);
		}
	}

	private async renderAuthenticationMethodSelection(req: Request, res: Response): Promise<any> {
		res.render('issuer/auth-method-selection', {
			title: "Authentication Method Selection",
			methods: this.availableAuthenticationMethods,
			lang: req.lang,
			locale: locale[req.lang]
		})
	}

}

