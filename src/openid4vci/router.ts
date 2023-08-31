import { Request, Response, Router } from "express";
import locale from "../locale";
import qs from "qs";
import 'reflect-metadata';
import { appContainer } from "../services/inversify.config";
import { CredentialIssuersConfigurationService } from "../configuration/CredentialIssuersConfigurationService";

const openid4vciRouter = Router();


openid4vciRouter.get('/init/view/:client_type', async (req: Request, res: Response) => {
	const credentialIssuerIdentifier = req.query["issuer"] as string;
	if (!credentialIssuerIdentifier) {
		console.error("Credential issuer identifier not found in params")
		return res.redirect('/');
	}

	const selectedCredentialIssuer = appContainer.resolve(CredentialIssuersConfigurationService)
		.registeredCredentialIssuerRepository()
		.getCredentialIssuer(credentialIssuerIdentifier);
	if (!selectedCredentialIssuer) {
		console.error("Credential issuer not map")
		return res.redirect('/')
	}
	const client_type = req.params.client_type;
	if (!client_type) {
		return res.redirect('/');
	}

	const credentialOfferObject = {
		credential_issuer: selectedCredentialIssuer.credentialIssuerIdentifier,
		credentials: [
			...selectedCredentialIssuer.supportedCredentials.map(sc => sc.exportCredentialSupportedObject())
		],
		grants: {
			authorization_code: { issuer_state: "123xxx" }
		}
	};
	const credentialOfferURL = "openid-credential-offer://?" + qs.stringify(credentialOfferObject);

	const parsed = qs.parse(credentialOfferURL.split('?')[1]);
	console.log("parsed = ", parsed)
	// credentialOfferURL.searchParams.append("credential_offer", qs.stringify(credentialOfferObject));
	
	switch (client_type) {
	case "DESKTOP":
		return res.render('issuer/init', {
			url: credentialOfferURL,
			qrcode: "",
			lang: req.lang,
			locale: locale[req.lang]
		})
	case "MOBILE":
		return res.redirect(credentialOfferURL);
	default:
		return res.redirect('/');
	}
})



export {
	openid4vciRouter
}