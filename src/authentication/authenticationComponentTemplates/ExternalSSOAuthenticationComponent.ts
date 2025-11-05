import { NextFunction, Request, Response } from "express";
import { ParamsDictionary } from "express-serve-static-core";
import { ParsedQs } from "qs";
import { AuthenticationComponent } from "../AuthenticationComponent";
import AppDataSource from "../../AppDataSource";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { UserAuthenticationMethod } from "../../types/UserAuthenticationMethod.enum";
import locale from "../../configuration/locale";
import titles from "../../configuration/titles";
import * as client from 'openid-client'
import { config } from "../../../config";
import axios from "axios";


function getByPath(obj: any, path: string[]) {
	return path.reduce((acc, key) => acc?.[key], obj);
}

export class ExternalSSOAuthenticationComponent extends AuthenticationComponent {

	serverUrl: URL;
	clientId: string;
	clientSecret: string;
	scope: string;
	callbackUrl: string;
	sessions: Map<string, { code_verifier: string, user: { session_id: string, } }> = new Map();

	constructor(
		override identifier: string,
		override protectedEndpoint: string,
		private mapping: { [authorizationServerStateColumnName: string]: { userInfoAttributePath: string[], parser?: (v: any) => string } },
		private defaultUsers?: Array<{ username: string, password: string }>
	) {
		super(identifier, protectedEndpoint)

		//@ts-ignore
		this.serverUrl = config.issuanceFlow?.authenticationComponentsConfigurations?.ssoAuthenticationComponent?.serverUrl ? new URL(config.issuanceFlow.authenticationComponentsConfigurations.ssoAuthenticationComponent.serverUrl) : null; // Authorization Server's Issuer Identifier
		if (!this.serverUrl) {
			throw new Error("Missing configuration attribute: config.issuanceFlow.authenticationComponentsConfigurations.ssoAuthenticationComponent.serverUrl");
		}
		//@ts-ignore
		this.clientId = config.issuanceFlow?.authenticationComponentsConfigurations?.ssoAuthenticationComponent?.clientId ?? null;
		if (!this.clientId) {
			throw new Error("Missing configuration attribute: config.issuanceFlow.authenticationComponentsConfigurations.ssoAuthenticationComponent.clientId");
		}
		// @ts-ignore
		this.clientSecret = config.issuanceFlow?.authenticationComponentsConfigurations?.ssoAuthenticationComponent?.clientSecret ?? null;
		if (!this.clientSecret) {
			throw new Error("Missing configuration attribute: config.issuanceFlow.authenticationComponentsConfigurations.ssoAuthenticationComponent.clientSecret");
		}
		// @ts-ignore
		this.scope = config.issuanceFlow?.authenticationComponentsConfigurations?.ssoAuthenticationComponent?.scope ?? null;
		if (!this.scope) {
			throw new Error("Missing configuration attribute: config.issuanceFlow.authenticationComponentsConfigurations.ssoAuthenticationComponent.scope");
		}
		this.callbackUrl = config.url + "/authorization/consent";
	}

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
			if (req.method == "GET" && req.query['code']) {
				return this.handleCallback(req, res);
			}

			return this.initiate(req, res);
		})
			.catch((err) => {
				console.error(err);
				return next();
			});
	}



	private async isAuthenticated(req: Request): Promise<boolean> {
		if (!req.query.state || !req.query.authenticated || req.query.authenticated !== 'true') {
			return false;
		}
		const sess = this.sessions.get(req.query.state as string);
		if (!sess) {
			console.error(`No active session found for state '${req.query.state as string}'`);
			return false;
		}
		const { user: { session_id } } = sess;
		const authorizationServerState = await AppDataSource.getRepository(AuthorizationServerState)
			.createQueryBuilder("authz_state")
			.where("authz_state.session_id = :session_id", { session_id: session_id })
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

	private async initiate(req: Request, res: Response): Promise<any> {
		const code_verifier = client.randomPKCECodeVerifier()
		const code_challenge = await client.calculatePKCECodeChallenge(code_verifier)
		const state = client.randomState();

		const config = await client.discovery(
			this.serverUrl,
			this.clientId,
			this.clientSecret,
		);
		this.sessions.set(state, { code_verifier, user: { session_id: req.cookies['session_id'] } });

		const parameters = {
			redirect_uri: this.callbackUrl,
			scope: this.scope,
			code_challenge,
			code_challenge_method: 'S256',
			state,
			prompt: 'login',
		};

		const redirectTo = client.buildAuthorizationUrl(config, parameters);
		res.redirect(redirectTo.toString());
	}

	private async renderFailedLogin(req: Request, res: Response): Promise<any> {
		res.render('issuer/login', {
			title: titles.index,
			defaultUsers: this.defaultUsers,
			lang: req.lang,
			locale: locale[req.lang],
			failed: true
		})
	}

	private async handleCallback(req: Request, res: Response): Promise<any> {
		const code = req.query.code;
		const state = req.query.state;
		if (!code || typeof code !== 'string') {
			console.error("authorization code is missing or is invalid");
			this.renderFailedLogin(req, res);
			return;
		}

		if (!state || typeof state !== 'string') {
			console.error("state is missing or is invalid");
			this.renderFailedLogin(req, res);
			return;
		}
		const configuration = await client.discovery(
			this.serverUrl,
			this.clientId,
			this.clientSecret,
		);
		const sess = this.sessions.get(state);
		if (!sess) {
			console.error(`No active session found for state '${state}'`);
			this.renderFailedLogin(req, res);
			return;
		}
		const { code_verifier } = sess;
		const tokens = await client.authorizationCodeGrant(
			configuration,
			new URL(`${this.callbackUrl}?code=${code}&state=${state}`),
			{
				pkceCodeVerifier: code_verifier,
				expectedState: state,
			},
		);
		const openidConfigurationReq = await axios.get(this.serverUrl.toString() + '/.well-known/openid-configuration');
		const { userinfo_endpoint, end_session_endpoint } = openidConfigurationReq.data as Record<string, unknown>;
		if (!userinfo_endpoint || typeof userinfo_endpoint !== 'string') {
			console.error("No userinfo_endpoint found in the openid configuration metadata");
			this.renderFailedLogin(req, res);
			return;
		}
		const protectedResourceResponse = await client.fetchProtectedResource(
			configuration,
			tokens.access_token,
			new URL(userinfo_endpoint),
			'GET',
		);
		const protectedResourceData = await protectedResourceResponse.json();
		console.log("Result of authorization: ", protectedResourceData);


		Object.keys(this.mapping).map((authorizationServerStateColumnName) => {
			const { userInfoAttributePath, parser } = this.mapping[authorizationServerStateColumnName];
			console.log("userInfoAttributePath = ", userInfoAttributePath)
			const parseFn = parser ?? ((value: string) => value);


			// @ts-ignore
			req.authorizationServerState[authorizationServerStateColumnName] = parseFn(getByPath(protectedResourceData, userInfoAttributePath));
		});

		await AppDataSource.getRepository(AuthorizationServerState).save(req.authorizationServerState);
		const returnUrl = new URL(req.originalUrl, config.url);
		returnUrl.searchParams.delete('code');
		returnUrl.searchParams.append('authenticated', 'true'); // this flag will be used to detect if the user is authenticated when returned after the end_session endpoint

		const endSessionUrl = new URL(end_session_endpoint as string);
		endSessionUrl.searchParams.append('post_logout_redirect_uri', returnUrl.toString());
		endSessionUrl.searchParams.append('id_token_hint', tokens.id_token as string);
		res.redirect(endSessionUrl.toString()); // redirect to the end session url, which will then redirect back to http://[wallet-enterprise]/authorization/consent?state=xxx&authenticated=true
	}
}
