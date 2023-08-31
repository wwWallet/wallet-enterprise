import { NextFunction, Request, Response } from "express";
import locale from "../locale";
import z from 'zod';
import _ from "lodash";
import { openidForCredentialIssuingAuthorizationServerService } from "../services/instances";
import { AuthorizationDetailsSchemaType, CredentialSupported } from "../types/oid4vci";
import axios from "axios";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
import { CredentialView } from "./types";




const consentSubmitSchema = z.object({
	selected_credential_id_list: z.array(z.string())
})

export async function consent(req: Request, res: Response, _next: NextFunction) {
	console.log("Consent = ", req.authorizationServerState)
	if (!req.authorizationServerState || !req.authorizationServerState.authorization_details) {
		res.render('error', {
			lang: req.lang,
			code: 0,
			msg: "Authorization server state is missing",
			locale: locale[req.lang]
		});
		return;
	}


	if (req.method == "POST") {
		try {
			const allCredentialViews = await getAllCredentialViews(req.authorizationServerState);
			const { selected_credential_id_list } = consentSubmitSchema.parse(req.body);
			console.log("Selected credential id list = ", req.body)
			const authorizationDetails = selected_credential_id_list.map((id) => {
					const credView = allCredentialViews.filter((credView) => credView.credential_id == id)[0];
					return credView ? { types: credView.credential_supported_object.types, format: credView.credential_supported_object.format, type: 'openid_credential' } : null;
				})
				.filter((ad) => ad != null) as AuthorizationDetailsSchemaType;
			await openidForCredentialIssuingAuthorizationServerService.sendAuthorizationResponse(
				req,
				res,
				req.authorizationServerState.id,
				authorizationDetails
			);

		}
		catch(err) {
			console.log(err);
			return res.render('error', {
				msg: `Invalid schema of form submission - ${err}`,
				lang: req.lang,
				locale: locale[req.lang]
			});
		}
	} // end of POST


	
	res.render('issuer/consent.pug', {
		title: 'Consent',
		redirect_uri: req.authorizationServerState.redirect_uri ? new URL(req.authorizationServerState.redirect_uri).hostname : "", 
		credentialViewList: await getAllCredentialViews(req.authorizationServerState),
		lang: req.lang,
		locale: locale[req.lang],
	});
}

async function getAllCredentialViews(authorizationServerState: AuthorizationServerState) {
	if (!authorizationServerState.authorization_details) {
		return [];
	}
	return (await Promise.all(authorizationServerState.authorization_details.map(async (ad) => {
		let credentialIssuerURL = "";
		if (ad.locations) {
			credentialIssuerURL = ad?.locations[0];
		}
		const cs = (await axios.get(credentialIssuerURL + "/.well-known/openid-credential-issuer"))
			.data
			.credentials_supported
			.filter((cs: any) => 
				ad.format == cs.format && _.isEqual(ad.types, cs.types)
			)[0] as CredentialSupported;
		console.log("Credential supported = ", cs);
		try {
			const { data: { credential_view } } = await axios.post(credentialIssuerURL + "/profile", { authorization_server_state: AuthorizationServerState.serialize(authorizationServerState), types: cs.types });
			if (!credential_view) {
				return null;
			}
			return credential_view as CredentialView;
		}
		catch(e: any) {
			console.error("Error while getting all credential views");
			if (e.response.data) {
				console.error(e.response.data);
			}
			return null;
		}

	}))).filter(res => res != null) as CredentialView[];
}