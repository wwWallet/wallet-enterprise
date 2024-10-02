import { NextFunction, Request, Response } from "express";
import z from 'zod';
import _ from "lodash";
import { credentialConfigurationRegistryService, openidForCredentialIssuingAuthorizationServerService } from "../services/instances";
import locale from "../configuration/locale";
import config from '../../config';
import AppDataSource from "../AppDataSource";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";


const consentSubmitSchema = z.object({
	selected_credential_id_list: z.array(z.string())
})

export async function consent(req: Request, res: Response, _next: NextFunction) {
	console.log("Consent page");
	console.log("AUTZ = ", req.authorizationServerState)

	if (!req.authorizationServerState) {
		res.render('error', {
			lang: req.lang,
			code: 0,
			msg: "Authorization server state is missing",
			locale: locale[req.lang]
		});
		return;
	}

	if (!req.authorizationServerState.credential_configuration_ids) {
		req.authorizationServerState.credential_configuration_ids = config?.issuanceFlow?.defaultCredentialConfigurationIds as string[] ?? [];
		await AppDataSource.getRepository(AuthorizationServerState).save(req.authorizationServerState);
	}


	const allCredentialViews = [ await credentialConfigurationRegistryService.getCredentialView(req.authorizationServerState) ].filter((result) => result != null);
	if ((config.issuanceFlow.skipConsent ?? false)) {
		return await openidForCredentialIssuingAuthorizationServerService.sendAuthorizationResponse(
			{req, res},
			req.authorizationServerState.id,
		);
	}

	if (req.method == "POST") {
		try {
			// at the moment the selected_credential_id_list is useless because only one credential per authorization request is supported
			// @ts-ignore
			const { selected_credential_id_list } = consentSubmitSchema.parse(req.body);
			return await openidForCredentialIssuingAuthorizationServerService.sendAuthorizationResponse(
				{ req, res },
				req.authorizationServerState.id,
			);

		}
		catch(err) {
			console.log(err);
		}
	} // end of POST


	// let credentialViewsWithCredentialOffers = null;
	// if (req.authorizationServerState.grant_type == GrantType.PRE_AUTHORIZED_CODE) {
	// 	credentialViewsWithCredentialOffers = await Promise.all(allCredentialViews.map(async (credentialView) => {
	// 		if (credentialView == null) {
	// 			return null;
	// 		}
	// 		const { url, user_pin_required, user_pin } = await openidForCredentialIssuingAuthorizationServerService
	// 			.generateCredentialOfferURL({req, res}, credentialView.credential_supported_object);
	// 		let credentialOfferQR = await new Promise((resolve) => {
	// 			qrcode.toDataURL(url.toString(), {
	// 				margin: 1,
	// 				errorCorrectionLevel: 'L',
	// 				type: 'image/png'
	// 			}, 
	// 			(err, data) => {
	// 				if (err) return resolve("NO_QR");
	// 				return resolve(data);
	// 			});
	// 		}) as string;
	// 		const credViewWithCredentialOffer = { 
	// 			...credentialView,
	// 			credentialOfferURL: url.toString(),
	// 			credentialOfferQR,
	// 			user_pin_required,
	// 			user_pin
	// 		};
	// 		return credViewWithCredentialOffer;
	// 	}));
	// }

	return res.render('issuer/consent.pug', {
		title: 'Consent',
		wwwalletURL: config.wwwalletURL,
		redirect_uri: req.authorizationServerState.redirect_uri ? new URL(req.authorizationServerState.redirect_uri).hostname : "", 
		credentialViewList: allCredentialViews,
		grant_type: req.authorizationServerState.grant_type,
		lang: req.lang,
		locale: locale[req.lang],
	});
}