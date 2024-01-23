import { Router } from "express";
// import { Repository } from "typeorm";
// import { VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
// import AppDataSource from "../AppDataSource";
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "../services/interfaces";
import { appContainer } from "../services/inversify.config";
import { TYPES } from "../services/types";
import locale from "../configuration/locale";
import * as qrcode from 'qrcode';
import base64url from "base64url";
import config from "../../config";

const verifierRouter = Router();
// const verifiablePresentationRepository: Repository<VerifiablePresentationEntity> = AppDataSource.getRepository(VerifiablePresentationEntity);
const verifierConfiguration = appContainer.get<VerifierConfigurationInterface>(TYPES.VerifierConfigurationServiceInterface);
const openidForPresentationReceivingService = appContainer.get<OpenidForPresentationsReceivingInterface>(TYPES.OpenidForPresentationsReceivingService);

verifierRouter.get('/public/definitions', async (req, res) => {
	
	return res.render('verifier/public_definitions.pug', {
		lang: req.lang,
		presentationDefinitions: verifierConfiguration.getPresentationDefinitions(),
		locale: locale[req.lang]
	})
})


verifierRouter.get('/success/status', async (req, res) => { // response with the status of the presentation (this endpoint should be protected)
	const state = req.query.state;
	const {status, presentation} = await openidForPresentationReceivingService.getPresentationByState(state as string);
	if (!presentation) {
		return res.send({ status: false, error: "Presentation not received" });
	}
	return res.send({ status, presentation });
})

verifierRouter.get('/success', async (req, res) => {
	const state = req.query.state;
	const {status, presentation} = await openidForPresentationReceivingService.getPresentationByState(state as string);
	if (!presentation) {
		return res.render('error.pug', {
			msg: "Failed to get presentation",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang],
		})
	}
	
	const presentationPayload = JSON.parse(base64url.decode(presentation.split('.')[1])) as any;
	const credentials = presentationPayload.vp.verifiableCredential.map((vcString: any) => {
		return JSON.parse(base64url.decode(vcString.split('.')[1]));
	}).map((credential: any) => credential.vc);

	console.log("Credential payloads = ", credentials)
	return res.render('verifier/success.pug', {
		lang: req.lang,
		locale: locale[req.lang],
		status: status,
		credentialPayloads: credentials
	})
})




verifierRouter.use('/public/definitions/presentation-request/:presentation_definition_id', async (req, res) => {
	const presentation_definition_id = req.params.presentation_definition_id;
	if (req.body.state && req.method == "POST") {
		console.log("Got state = ", req.body.state)
		const { status } = await openidForPresentationReceivingService.getPresentationByState(req.body.state as string);
		if (status) {
			return res.redirect(`/verifier/success?state=${req.body.state}`);
		}
		else {
			return res.render('verifier/QR.pug', {
				state: req.body.state,
				authorizationRequestURL: req.body.authorizationRequestURL,
				authorizationRequestQR: req.body.authorizationRequestQR,
				lang: req.lang,
				locale: locale[req.lang],
			})
		}
	}

	if (!presentation_definition_id) {
		return res.render('error', {
			msg: "No presentation definition was selected",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}

	const presentationDefinition = verifierConfiguration.getPresentationDefinitions().filter(pd => pd.id == presentation_definition_id)[0];
	if (!presentationDefinition) {
		return res.render('error', {
			msg: "No presentation definition was found",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}

	const { url } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({req, res}, presentationDefinition.id, config.url + "/verifier/success");	
	let authorizationRequestQR = await new Promise((resolve) => {
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

	console.log("URL = ", url)
	return res.render('verifier/QR.pug', {
		authorizationRequestURL: url.toString(),
		authorizationRequestQR,
		state: url.searchParams.get('state'),
		lang: req.lang,
		locale: locale[req.lang],
	})
})


export { verifierRouter };