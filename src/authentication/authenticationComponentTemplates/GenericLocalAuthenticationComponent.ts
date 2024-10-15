import { NextFunction, Request, Response } from "express";
import { ParamsDictionary } from "express-serve-static-core";
import { ParsedQs } from "qs";
import { AuthenticationComponent } from "../AuthenticationComponent";
import AppDataSource from "../../AppDataSource";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { UserAuthenticationMethod } from "../../types/UserAuthenticationMethod.enum";
import locale from "../../configuration/locale";

export class GenericLocalAuthenticationComponent extends AuthenticationComponent {

	constructor(
		override identifier: string,
		override protectedEndpoint: string,
		private mapping: { [authorizationServerStateColumnName: string] : { datasetColumnName: string, parser?: (v: any) => string }},
		private datasetProvider: () => Promise<Array<any>>,
		private defaultUsers?: Array<{ username: string, password: string }>
	) { super(identifier, protectedEndpoint) }

	public override async authenticate(
		req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
		res: Response<any, Record<string, any>>,
		next: NextFunction) {
		
		return super.authenticate(req, res, async () => {
			if (await this.isAuthenticated(req).catch(() => false)) {
				return next();
			}
	
			if (req.authorizationServerState.authenticationMethod &&
				req.authorizationServerState.authenticationMethod != UserAuthenticationMethod.SSO) {
					
				return next();
			}
			if (req.method == "POST") {
				return this.handleLoginSubmission(req, res);
			}
	
			return this.renderLogin(req, res);
		})
		.catch(() => {
			return next();
		});
	}


	
	private async isAuthenticated(req: Request): Promise<boolean> {
		if (!req.cookies['session_id']) {
			return false;
		}
		const authorizationServerState = await AppDataSource.getRepository(AuthorizationServerState)
			.createQueryBuilder("authz_state")
			.where("authz_state.session_id = :session_id", { session_id: req.cookies['session_id'] })
			.getOne();

		if (!authorizationServerState) {
			return false;
		}

		const extractedValues = Object.keys(this.mapping).map((authorizationServerStateColumnName) => {
			// @ts-ignore
			return authorizationServerState[authorizationServerStateColumnName];		
		}).filter((x) => x != undefined && x != null);

		console.log("Extracted values = ", extractedValues);
		if (extractedValues.length == Object.keys(this.mapping).length) {
			return true;
		}
		return false;
	}

	private async renderLogin(req: Request, res: Response): Promise<any> {
		res.render('issuer/login', {
			title: "Login",
			defaultUsers: this.defaultUsers,
			lang: req.lang,
			locale: locale[req.lang]
		})
	}

	private async renderFailedLogin(req: Request, res: Response): Promise<any> {
		res.render('issuer/login', {
			title: "Login",
			lang: req.lang,
			locale: locale[req.lang],
			failed: true
		})
	}

	private async handleLoginSubmission(req: Request, res: Response): Promise<any> {
		// const users = parseEhicData(path.join(__dirname, "../../../../dataset/ehic-dataset.xlsx"));

		const users = await this.datasetProvider();
		if (!users) {
			throw new Error("Failed to load users");
		}
		const { username, password } = req.body;
		const usersFound = users.filter(u => u.User == username && u.Password == password);
		if (usersFound.length > 0) {

			Object.keys(this.mapping).map((authorizationServerStateColumnName) => {
				const { datasetColumnName, parser } = this.mapping[authorizationServerStateColumnName];
				console.log("Dataset column name = ", datasetColumnName)
				console.log("column parser = ", parser)
				const columnParser = parser ?? ((value: string) => value);
	
				// @ts-ignore
				req.authorizationServerState[authorizationServerStateColumnName] = columnParser(usersFound[0][datasetColumnName]);
			});
			// req.authorizationServerState.family_name = String(usersFound[0].family_name);
			// req.authorizationServerState.given_name = String(usersFound[0].given_name);
			// req.authorizationServerState.birth_date = String(new Date(usersFound[0].birth_date).toISOString());

			await AppDataSource.getRepository(AuthorizationServerState).save(req.authorizationServerState);
			return res.redirect(this.protectedEndpoint);
		}
		else {
			return this.renderFailedLogin(req, res);
		}
	}
}


