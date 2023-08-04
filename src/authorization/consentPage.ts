import { NextFunction, Request, Response } from "express";
import { UserSession, redisModule } from "../RedisModule";
import { CredentialView } from "./types";
import locale from "../locale";
import { CategorizedRawCredential } from "../openid4vci/Metadata";
import z from 'zod';
import { defaultIssuer, issuersConfigurations } from "../configuration/IssuersConfiguration";
import { CredentialIssuerConfig } from "../lib/CredentialIssuerConfig/CredentialIssuerConfig";
import _ from "lodash";
import { appContainer } from "../services/inversify.config";
import { OpenidForCredentialIssuingService } from "../services/OpenidForCredentialIssuingService";
import { AuthorizationDetailsSchemaType } from "../types/oid4vci";




const consentSubmitSchema = z.object({
	selected_credential_id_list: z.array(z.string())
})

export async function consent(req: Request, res: Response, _next: NextFunction) {
	if (req.userSession?.id) {
		await loadCategorizedRawCredentialsToUserSession(req, req.userSession?.id as string);
	}
	
	const openidForCredentialIssuingService = appContainer.resolve(OpenidForCredentialIssuingService);
	if (!req.userSession || !req.userSession.authorizationDetails) {
		res.render('error');
		return;
	}

	if (req.method == "POST") {
		try {
			const { selected_credential_id_list } = consentSubmitSchema.parse(req.body);
			console.log("Selected credential id list = ", req.body)
			if (!req.userSession.categorizedRawCredentials) {
				const error = {
					code: "undefined",
					error: "No categorizedRawCredentials were found",
					error_description: "On POST of consent page, categorizedRawCredentials is empty"
				}
				console.error(error);
				return res.render('error', error);
			}
			req.userSession.categorizedRawCredentials = req.userSession.categorizedRawCredentials
				.filter(cred => 
					selected_credential_id_list.includes(cred.credential_id)
				);
			await redisModule.storeUserSession(req.userSession.id, req.userSession);
			await openidForCredentialIssuingService.sendAuthorizationResponse(
				req,
				res,
				req.userSession.id,
				selected_credential_id_list
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

	const userSession = await redisModule.getUserSession(req.userSession.id);
	const credViewList = userSession?.credViewList;

	res.render('issuer/consent.pug', {
		credentialViewList: credViewList,
		title: 'Consent',
		lang: req.lang,
		locale: locale[req.lang],
	});
}

/**
 * This function could be called multiple times.
 * Once on the ID Token Response
 * and once at the end of the Authentication Components.
 * @throws
 * @param req 
 */
export async function loadCategorizedRawCredentialsToUserSession(req: Request, userSessionId: string) {
	const userSession = await redisModule.getUserSession(userSessionId);

	if (!userSession) {
		console.log("User session = ", req.userSession)
		throw new Error("Could not load categorized raw credentials to session")
	}
	const credentials: CategorizedRawCredential<any>[] = [ ];
	const credViewList: CredentialView[] = [];


	// if no authorization details were found, then load all the supported credentials from the default issuer.
	if (!userSession.authorizationDetails) {
		const authorizationDetails = [ ...defaultIssuer.supportedCredentials.map((sc) => sc.exportCredentialSupportedObject()) ].map((sc) => {
			return { 
				type: "openid_credential",
				types: sc.types ? [ ...sc.types ] : [],
				format: sc.format,
				locations: [ defaultIssuer.credentialIssuerIdentifier ]
			}
		}) as AuthorizationDetailsSchemaType;
		userSession.authorizationDetails = authorizationDetails;
	}

	for (const authorizationDetail of userSession.authorizationDetails) {
		// find the selected issuer by the locations parameter, else by the default credential issuer identifier
		const credentialIssuerIdentifier = authorizationDetail.locations && authorizationDetail.locations.length 
			? authorizationDetail.locations[0]
			: defaultIssuer.credentialIssuerIdentifier;

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

	userSession.categorizedRawCredentials = credentials;
	userSession.credViewList = credViewList;

	console.log("User session = ", req.userSession)
	// update on redis
	try {
		await redisModule.storeUserSession(userSession.id, userSession);
		req.userSession = userSession; // update the object
	}
	catch(e) {
		console.error("Failed to loadCategorizedRawCredentialsToUserSession in cache");
	}

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