import { Router } from "express";
// import { Repository } from "typeorm";
// import { VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
// import AppDataSource from "../AppDataSource";
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "../services/interfaces";
import { appContainer } from "../services/inversify.config";
import { TYPES } from "../services/types";
import locale from "../configuration/locale";
import * as qrcode from 'qrcode';

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



verifierRouter.get('/public/definitions/presentation-request/:presentation_definition_id', async (req, res) => {
	const presentation_definition_id = req.params.presentation_definition_id;
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

	const { url } = await openidForPresentationReceivingService.generateAuthorizationRequestURL(presentationDefinition.id);
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


	return res.render('verifier/QR.pug', {
		lang: req.lang,
		authorizationRequestURL: url.toString(),
		authorizationRequestQR,
		locale: locale[req.lang],
	})
})


export { verifierRouter };