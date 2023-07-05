import { Request, Response } from "express";
import { UserSession, redisModule } from "../RedisModule";
import { CredentialView } from "./types";
import locale from "../locale";
import { CategorizedRawCredential } from "../openid4vci/Metadata";
import { generateAuthorizationResponse } from "../openid4vci/endpoints/authorizationEndpoint";
import z from 'zod';
import { issuersConfigurations } from "../configuration/IssuersConfiguration";
import { CredentialIssuerConfig } from "../lib/CredentialIssuerConfig/CredentialIssuerConfig";
import _ from "lodash";
import config from "../../config";
const consentSubmitSchema = z.object({
	selected_credential_id_list: z.array(z.string())
})

export async function consent(req: Request, res: Response) {
	if (!req.userSession || !req.userSession.authorizationDetails) {
		res.render('error');
		return;
	}

	if (req.method == "POST") {
		try {
			const { selected_credential_id_list } = consentSubmitSchema.parse(req.body);
			console.log("Selected credential id list = ", req.body)
			const { authorizationResponseURL } = await generateAuthorizationResponse(req.userSession, selected_credential_id_list);
			if (!req.userSession.categorizedRawCredentials) {
				return res.render('error');
			}
			req.userSession.categorizedRawCredentials = req.userSession.categorizedRawCredentials.filter(cred => selected_credential_id_list.includes(cred.credential_id));
			await redisModule.storeUserSession(req.userSession.id, req.userSession);
			return res.redirect(authorizationResponseURL);
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


	const credentials: CategorizedRawCredential<any>[] = [ ];
	const credViewList: CredentialView[] = [];

	for (const authorizationDetail of req.userSession.authorizationDetails) {
		// find the selected issuer by the locations parameter, else by the default credential issuer identifier
		const credentialIssuerIdentifier = authorizationDetail.locations && authorizationDetail.locations.length ? authorizationDetail.locations[0] : config.url;
		const issuerConfiguration = issuersConfigurations.get(credentialIssuerIdentifier);
		if (!issuerConfiguration)
			continue;

		// for each supported credentials, get resources
		const resourceResponsesPromises = issuerConfiguration.supportedCredentials
			.map(sc => 
				sc.getFormat() == authorizationDetail.format && _.isEqual(sc.getTypes(), authorizationDetail.types) ? 
				sc.getResources(req.userSession as UserSession) :
				[]
			);
		const resourceResponses = await Promise.all(resourceResponsesPromises);

		// push all found resources into the credentials array
		for (const resourceResponse of resourceResponses) {
			credentials.push(...resourceResponse);

			// store all credential views
			credViewList.push(...resourceResponse.map(credential => constructView(issuerConfiguration, credential)));
		}

	}

	req.userSession.categorizedRawCredentials = credentials;
	console.log("User session = ", req.userSession)
	redisModule.storeUserSession(req.userSession.id, req.userSession).catch(err => {
		console.log("Redis could not store userSession")
		console.log(err)
	});


	res.render('issuer/consent.pug', {
		credentialViewList: credViewList,
		title: 'Consent',
		lang: req.lang,
		locale: locale[req.lang],
	});
}


function constructView(issuerConfiguration: CredentialIssuerConfig, credential: CategorizedRawCredential<any>): CredentialView {
	const supportedCredential = issuerConfiguration.supportedCredentials.filter(sc => sc.getId() == credential.supportedCredentialIdentifier)[0];
	const logo =  supportedCredential.getDisplay().logo?.url;
	if (!logo) {
		console.log("no logo was found")
		throw "No logo was found";
	}
	return {
		credential_id: credential.credential_id,
		credential_logo_url: logo,
		credentialSubject: {},
		data: credential.rawData,
		view: credential.view
	}	
}