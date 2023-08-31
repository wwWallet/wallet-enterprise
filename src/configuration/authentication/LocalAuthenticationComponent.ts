import { NextFunction, Request, Response } from "express";
import { ParamsDictionary } from "express-serve-static-core";
import { SignJWT, jwtVerify } from "jose";
import { ParsedQs } from "qs";
import { AuthenticationComponent } from "../../authentication/AuthenticationComponent";
import locale from "../../locale";
import AppDataSource from "../../AppDataSource";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";




export class LocalAuthenticationComponent extends AuthenticationComponent {

	constructor(
		override identifier: string,
		override protectedEndpoint: string,
		private secret = "dferfrewterwtretetetet",
		private users = [ { username: "user", password: "123", taxis_id: "user" }, { username: "user2", password: "secret", taxis_id: "user" }]
	) { super(identifier, protectedEndpoint) }

	public override async authenticate(
		req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
		res: Response<any, Record<string, any>>,
		next: NextFunction) {
		
		return super.authenticate(req, res, async () => {
			if (await this.isAuthenticated(req)) {
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
		const jws = req.cookies['jws'];
		if (!jws) {
			return false;
		}
		return jwtVerify(jws, new TextEncoder().encode(this.secret)).then(result => {
			const username = result.payload.sub;
			if (!username) return false;
			return (this.users.filter(u => u.username == username).length == 1);
		}).catch(err => {
			console.error(err);
			return false;
		})
	}

	private async renderLogin(req: Request, res: Response): Promise<any> {
		res.render('issuer/login', {
			title: "Login1",
			lang: req.lang,
			locale: locale[req.lang]
		})
	}

	private async handleLoginSubmission(req: Request, res: Response): Promise<any> {
		const { username, password } = req.body;
		const usersFound = this.users.filter(u => u.username == username && u.password == password);
		if (usersFound.length == 1) {
			// sign a token and send it to the client

			const jws = await new SignJWT({})
				.setSubject(username)
				.setProtectedHeader({ alg: 'HS256' })
				.setIssuedAt()
				.setExpirationTime('1h')
				.sign(new TextEncoder().encode(this.secret));
			res.cookie('jws', jws);

			req.authorizationServerState.taxis_id = usersFound[0].taxis_id;
			await AppDataSource.getRepository(AuthorizationServerState).save(req.authorizationServerState);
			return res.redirect(this.protectedEndpoint);
		}
		else {
			return this.renderLogin(req, res);
		}
	}
}


