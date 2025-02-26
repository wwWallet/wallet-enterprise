import { NextFunction, Request, Response } from "express";
import { ParamsDictionary } from "express-serve-static-core";
import { ParsedQs } from "qs";
import { AuthenticationComponent } from "../../authentication/AuthenticationComponent";
import AppDataSource from "../../AppDataSource";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { config } from "../../../config";
import { CONSENT_ENTRYPOINT } from "../../authorization/constants";
import { openidForPresentationReceivingService, verifierConfigurationService } from "../../services/instances";
import { UserAuthenticationMethod } from "../../types/UserAuthenticationMethod.enum";
import { appContainer } from "../../services/inversify.config";
import { OpenidForPresentationsReceivingService } from "../../services/OpenidForPresentationReceivingService";
import locale from "../../configuration/locale";
import { RelyingPartyState } from "../../entities/RelyingPartyState.entity";

export class GenericVIDAuthenticationComponent extends AuthenticationComponent {
	private openidForPresentationReceivingService = appContainer.resolve(OpenidForPresentationsReceivingService);

	constructor(
		override identifier: string,
		override protectedEndpoint: string,
		private mapping: { [authorizationServerStateColumnName: string] : { input_descriptor_constraint_field_name: string, parser?: (v: any) => string }},
		private presentationDefinitionId: string = "vid",
		private inputDescriptorId: string = "VID",
		private scopeName: string
	) { super(identifier, protectedEndpoint) }

	public override async authenticate(
		req: Request<ParamsDictionary, any, any, ParsedQs, Record<string, any>>,
		res: Response<any, Record<string, any>>,
		next: NextFunction) {

		return super.authenticate(req, res, async () => {
			if (await this.dataHaveBeenExtracted(req)) {
				return next();
			}

			if (req.authorizationServerState.authenticationMethod &&
					req.authorizationServerState.authenticationMethod != UserAuthenticationMethod.VID_AUTH) {
				return next();
			}

			if (req.method == 'GET' && req.originalUrl.endsWith('/callback')) {
				console.log("rendering verifier/handle-response-code view...")
				return res.render('verifier/handle-response-code', {
					lang: req.lang,
					locale: locale[req.lang],
				})
			}

			if (req.method == 'POST' && req.originalUrl.endsWith('/callback')) {
				const result = await this.handleCallback(req, res);
				if (result.error) {
					return res.render('error', {
						title: "Verification Error",
						msg: result.error,
						lang: req.lang,
						locale: locale[req.lang],
					})
				}
				return;
			}
			return this.askForPresentation(req, res);
		})
		.catch(() => {
			return next();
		});
	}

	private async dataHaveBeenExtracted(req: Request): Promise<boolean> {
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
			return true
		}
		return false;
	}

	private async handleCallback(req: Request, res: Response): Promise<{ error?: Error }> {
		if (!req.cookies['session_id']) {
			return { error: new Error("Misssing Session id") };
		}
		const result = await this.openidForPresentationReceivingService.getPresentationBySessionIdOrPresentationDuringIssuanceSession(req.cookies['session_id']);
		if (!result.status) {
			return { error: result.error };
		}
		const vp_token = result.rpState.vp_token;

		console.log("Result = ", result)
		const authorizationServerState = await AppDataSource.getRepository(AuthorizationServerState)
			.createQueryBuilder("authz_state")
			.where("authz_state.session_id = :session_id", { session_id: result.rpState.session_id })
			.getOne();
		
		console.log("Authorization server state = ", authorizationServerState)

		if (!authorizationServerState || !vp_token || !result.rpState.claims || !result.rpState.claims[this.inputDescriptorId]) {
			return { error: new Error("Requested attributes are missing") };
		}


		Object.keys(this.mapping).map((authorizationServerStateColumnName) => {
			const { input_descriptor_constraint_field_name, parser } = this.mapping[authorizationServerStateColumnName];
			console.log("Field name = ", input_descriptor_constraint_field_name)
			console.log("Field parser = ", parser)
			const fieldParser = parser ?? ((value: string) => value);

			// @ts-ignore
			authorizationServerState[authorizationServerStateColumnName] = fieldParser(result.rpState.claims[this.inputDescriptorId].filter((claim) => claim.name == input_descriptor_constraint_field_name)[0].value ?? null)
		});

		await AppDataSource.getRepository(AuthorizationServerState).save(authorizationServerState);
		res.redirect(this.protectedEndpoint);
		return { };
	}

	private async askForPresentation(req: Request, res: Response): Promise<any> {
		let presentationDefinition = JSON.parse(JSON.stringify(verifierConfigurationService.getPresentationDefinitions().filter(pd => pd.id == this.presentationDefinitionId)[0])) as any;
		presentationDefinition.input_descriptors[0].purpose = `Present your credential(s) to get your ${this.scopeName}`
		try {
			const { url, stateId } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({req, res}, presentationDefinition, req.cookies['session_id'], config.url + CONSENT_ENTRYPOINT + '/callback');
			console.log("Authorization request url = ", url)
			// attach the vid_auth_state with an authorization server state
			req.authorizationServerState.vid_auth_state = stateId;
			await AppDataSource.getRepository(AuthorizationServerState).save(req.authorizationServerState);
			console.log("Authz state = ", req.authorizationServerState)
					// update is_cross_device --> false since the button was pressed
			await AppDataSource.getRepository(RelyingPartyState).createQueryBuilder("rp_state")
				.update({ is_cross_device: false })
				.where("session_id = :session_id", { session_id: req.cookies.session_id })
				.execute();
			return res.render('issuer/vid-auth-component', {
				authorizationRequestURL: url.toString(),
				lang: req.lang,
				locale: locale[req.lang],
			})
			// return res.redirect(url.toString());

		}
		catch(err) {
			console.log(err);
			return res.redirect('/');
		}

	}
	
}
