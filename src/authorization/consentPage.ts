import { NextFunction, Request, Response } from "express";
import z from 'zod';
import _ from "lodash";
import { openidForCredentialIssuingAuthorizationServerService } from "../services/instances";
import { AuthorizationDetailsSchemaType, CredentialSupported, GrantType } from "../types/oid4vci";
import axios from "axios";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
import { CredentialView } from "./types";
import locale from "../configuration/locale";
import { SKIP_CONSENT } from "../configuration/consent/consent.config";
import * as qrcode from 'qrcode';
import config from '../../config';


const consentSubmitSchema = z.object({
	selected_credential_id_list: z.array(z.string())
})

export async function consent(req: Request, res: Response, _next: NextFunction) {
	console.log('Consent Body = ', req.body)

	console.log("AUTZ = ", req.authorizationServerState)
	if (!req.authorizationServerState || !req.authorizationServerState.authorization_details) {
		res.render('error', {
			lang: req.lang,
			code: 0,
			msg: "Authorization server state is missing",
			locale: locale[req.lang]
		});
		return;
	}


	const allCredentialViews = await getAllCredentialViews(req.authorizationServerState);

	if (SKIP_CONSENT) {
		return await openidForCredentialIssuingAuthorizationServerService.sendAuthorizationResponse(
			{req, res},
			req.authorizationServerState.id,
			req.authorizationServerState.authorization_details
		);
	}

	if (req.method == "POST") {
		try {
			const { selected_credential_id_list } = consentSubmitSchema.parse(req.body);
			console.log("Selected credential id list = ", req.body)
			const authorizationDetails = selected_credential_id_list.map((id) => {
					const credView = allCredentialViews.filter((credView) => credView.credential_id == id)[0];
					return credView ? { types: credView.credential_supported_object.types, format: credView.credential_supported_object.format, type: 'openid_credential' } : null;
				})
				.filter((ad) => ad != null) as AuthorizationDetailsSchemaType;
			return await openidForCredentialIssuingAuthorizationServerService.sendAuthorizationResponse(
				{ req, res },
				req.authorizationServerState.id,
				authorizationDetails
			);

		}
		catch(err) {
			console.log(err);
			// return res.render('error', {
			// 	msg: `Invalid schema of form submission - ${err}`,
			// 	lang: req.lang,
			// 	locale: locale[req.lang]
			// });
		}
	} // end of POST


	let credentialViewsWithCredentialOffers = null;
	if (req.authorizationServerState.grant_type == GrantType.PRE_AUTHORIZED_CODE) {
		credentialViewsWithCredentialOffers = await Promise.all(allCredentialViews.map(async (credentialView) => {
			const { url, user_pin_required, user_pin } = await openidForCredentialIssuingAuthorizationServerService
				.generateCredentialOfferURL({req, res}, credentialView.credential_supported_object, GrantType.PRE_AUTHORIZED_CODE);
			let credentialOfferQR = await new Promise((resolve) => {
				qrcode.toDataURL(url.toString(), {
					margin: 1,
					errorCorrectionLevel: 'L',
					type: 'image/png'
				}, 
				(err, data) => {
					if (err) return resolve("NO_QR");
					return resolve(data);
				});
			}) as string;
			const credViewWithCredentialOffer = { 
				...credentialView,
				credentialOfferURL: url.toString(),
				credentialOfferQR,
				user_pin_required,
				user_pin
			};
			return credViewWithCredentialOffer;
		}));
	}

	return res.render('issuer/consent.pug', {
		title: 'Consent',
		wwwalletURL: config.wwwalletURL,
		redirect_uri: req.authorizationServerState.redirect_uri ? new URL(req.authorizationServerState.redirect_uri).hostname : "", 
		credentialViewList: req.authorizationServerState.grant_type == GrantType.PRE_AUTHORIZED_CODE ?
			credentialViewsWithCredentialOffers :
			allCredentialViews,
		grant_type: req.authorizationServerState.grant_type,
		lang: req.lang,
		locale: locale[req.lang],
	});
}

async function getAllCredentialViews(authorizationServerState: AuthorizationServerState) {
	if (!authorizationServerState.authorization_details) {
		return [];
	}

	console.log("Credential issuer id = ", authorizationServerState.credential_issuer_identifier)
	return (await Promise.all(authorizationServerState.authorization_details.map(async (ad) => {
		try {
			const credentialSupported = (await axios.get(authorizationServerState.credential_issuer_identifier + "/.well-known/openid-credential-issuer"))
			.data
			.credentials_supported
			.filter((cs: any) => 
				ad.format == cs.format && _.isEqual(ad.types, cs.types)
			)[0] as CredentialSupported;

			const { data: { credential_view } } = await axios.post(authorizationServerState.credential_issuer_identifier + "/profile", {
				authorization_server_state: AuthorizationServerState.serialize(authorizationServerState),
				types: credentialSupported.types
			});
			if (!credential_view) {
				return null;
			}
			return credential_view as CredentialView;
		}
		catch(e: any) {
			console.error("Error while getting all credential views");
			if (e.response && e.response.data) {
				console.error(e.response.data);
			}
			else {
				console.error(e);
			}
			return null;
		}

	}))).filter(res => res != null) as CredentialView[];
}