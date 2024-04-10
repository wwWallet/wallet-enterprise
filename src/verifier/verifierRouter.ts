import { Router } from "express";
// import { Repository } from "typeorm";
// import { VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
// import AppDataSource from "../AppDataSource";
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "../services/interfaces";
import { appContainer } from "../services/inversify.config";
import { TYPES } from "../services/types";
import locale from "../configuration/locale";
import * as qrcode from 'qrcode';
import config from "../../config";
import base64url from "base64url";
import { PresentationDefinitionTypeWithFormat } from "../configuration/verifier/VerifierConfigurationService";

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
	const {status, presentationClaims, rawPresentation } = await openidForPresentationReceivingService.getPresentationByState(state as string);
	if (!presentationClaims) {
		return res.send({ status: false, error: "Presentation not received" });
	}
	return res.send({ status, presentationClaims, presentation: rawPresentation });
})

verifierRouter.get('/success', async (req, res) => {
	const state = req.query.state;
	const {status, presentationClaims, rawPresentation } = await openidForPresentationReceivingService.getPresentationByState(state as string);
	if (!presentationClaims || !rawPresentation) {
		return res.render('error.pug', {
			msg: "Failed to get presentation",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang],
		})
	}
	
	const presentationPayload = JSON.parse(base64url.decode(rawPresentation.split('.')[1])) as any;
	const credentials = presentationPayload.vp.verifiableCredential.map((vcString: any) => {
		return JSON.parse(base64url.decode(vcString.split('.')[1]));
	}).map((credential: any) => credential.vc);

	return res.render('verifier/success.pug', {
		lang: req.lang,
		locale: locale[req.lang],
		status: status,
		presentationClaims: presentationClaims,
		credentialPayloads: credentials,
	})
})


verifierRouter.use('/public/definitions/selectable-presentation-request/:presentation_definition_id', async (req, res) => {
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
	return res.render('verifier/selectable_presentation', {
		presentationDefinitionId: presentationDefinition.id,
		lang: req.lang,
		locale: locale[req.lang],
	});
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
				wwwalletURL: config.wwwalletURL,
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

	const presentationDefinition = JSON.parse(JSON.stringify(verifierConfiguration.getPresentationDefinitions().filter(pd => pd.id == presentation_definition_id)[0])) as PresentationDefinitionTypeWithFormat;
	if (!presentationDefinition) {
		return res.render('error', {
			msg: "No presentation definition was found",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}

	// If there are selected fields from a POST request, update the constraints accordingly
	if (req.method === "POST" && req.body.fields) {
		let selectedFields = req.body.fields;
		if (!Array.isArray(selectedFields)) {
			selectedFields = [selectedFields];
		}
		const selectedPaths = new Set(selectedFields.map((field: string) => {
			if (field === "type") {
				return `$.${field}`;
			} else {
				return `$.credentialSubject.${field}`;
			}
		}));
		// Filter existing paths to keep only those selected by the user and update presentationDefinition
		const availableFields = presentationDefinition.input_descriptors[0].constraints.fields;
		console.log("Available fields = ", availableFields)
		const filteredFields = presentationDefinition.input_descriptors[0].constraints.fields.filter(field =>
			selectedPaths.has(field.path[0])
		);

		console.log("filtered fields = ", filteredFields)
		presentationDefinition.input_descriptors[0].constraints.fields = filteredFields;
	}

	const { url } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({req, res}, presentationDefinition, config.url + "/verifier/success");	
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
		wwwalletURL: config.wwwalletURL,
		authorizationRequestURL: url.toString(),
		authorizationRequestQR,
		state: url.searchParams.get('state'),
		lang: req.lang,
		locale: locale[req.lang],
	})
})


export { verifierRouter };