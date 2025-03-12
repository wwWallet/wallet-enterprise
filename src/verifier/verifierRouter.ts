import { Router } from "express";
// import { Repository } from "typeorm";
// import { VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
// import AppDataSource from "../AppDataSource";
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "../services/interfaces";
import { appContainer } from "../services/inversify.config";
import { TYPES } from "../services/types";
import locale from "../configuration/locale";
import * as qrcode from 'qrcode';
import { config } from "../../config";

import { generateRandomIdentifier } from "../lib/generateRandomIdentifier";
import { addSessionIdCookieToResponse } from "../sessionIdCookieConfig";
import AppDataSource from "../AppDataSource";
import { RelyingPartyState } from "../entities/RelyingPartyState.entity";
import { initializeCredentialEngine } from "../lib/initializeCredentialEngine";


export enum CredentialFormat {
	VC_SD_JWT = "vc+sd-jwt",
	JWT_VC_JSON = "jwt_vc_json"
}


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


verifierRouter.get('/callback/status', async (req, res) => { // response with the status of the presentation (this endpoint should be protected)
	if (!req.cookies['session_id']) {
		return res.send({ status: false, error: "Missing session_id from cookies" });
	}
	const result = await openidForPresentationReceivingService.getPresentationBySessionIdOrPresentationDuringIssuanceSession(req.cookies['session_id']);
	if (!result.status) {
		return res.send({ status: false, error: "Presentation not received" });
	}
	return res.send({ status: result.status, presentationClaims: result.rpState.claims, presentation: result.rpState.vp_token });
})


verifierRouter.get('/callback', async (req, res) => {
	res.render('verifier/handle-response-code', {
		lang: req.lang,
		locale: locale[req.lang],
	})
})

verifierRouter.post('/callback', async (req, res) => {
	// this request includes the response code
	let session_id = req.cookies['session_id'];
	if (req.body.response_code) { // response_code is considered more stable than session_id
		const s = await AppDataSource.getRepository(RelyingPartyState).createQueryBuilder()
			.where("response_code = :response_code", { response_code: req.body.response_code })
			.getOne();
		if (s) {
			session_id = s.session_id;
		}
	}

	if (!session_id) {
		console.error("Problem with the verification flow")
		return res.status(400).send({ error: "Problem with the verification flow" })
	}

	const result = await openidForPresentationReceivingService.getPresentationBySessionIdOrPresentationDuringIssuanceSession(session_id);

	if (result.status == false ||
		result.rpState.vp_token == null ||
		result.rpState.claims == null ||
		result.rpState.date_created == null) {
		return res.render('error.pug', {
			msg: result.status == false ? result.error.message : "Unknown error",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang],
		})
	}

	const { claims, date_created } = result.rpState;
	const presentations = result.presentations;
	const status = result.status;

	const credentialImages = [];
	const credentialPayloads = [];
	for (const p of presentations) {
		const { credentialParsingEngine } = initializeCredentialEngine();
		const result = await credentialParsingEngine.parse({ rawCredential: p });
		if (result.success) {
			credentialImages.push(result.value.metadata.credential.image.dataUri);
			credentialPayloads.push(result.value.signedClaims);
		}
	}

	return res.render('verifier/success.pug', {
		lang: req.lang,
		locale: locale[req.lang],
		status: status,
		verificationTimestamp: date_created.toISOString(),
		presentationClaims: claims,
		credentialPayloads: credentialPayloads,
		credentialImages: credentialImages,
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
	if (presentationDefinition.input_descriptors.length > 1) {
		throw new Error("Selectable presentation definition is not supported for more than one descriptors currently");
	}
	const selectableFields = presentationDefinition.input_descriptors[0].constraints.fields.map((field: any) => {
		return [field.name, field.path[0]]
	});

	console.log("Selectable fields = ", selectableFields)
	return res.render('verifier/selectable_presentation', {
		presentationDefinitionId: presentationDefinition.id,
		selectableFields,
		lang: req.lang,
		locale: locale[req.lang],
	});
})



verifierRouter.get('/public/definitions/presentation-request/status/:presentation_definition_id', async (req, res) => {
	console.log("session_id : ", req.cookies['session_id'])
	if (req.cookies['session_id'] && req.method == "GET") {
		const { status } = await openidForPresentationReceivingService.getPresentationBySessionIdOrPresentationDuringIssuanceSession(req.cookies['session_id']);
		if (status == true) {
			return res.send({ url: `/verifier/callback` });
		}
		else {
			return res.send({});
		}
	}
	else {
		return res.send({})
	}
})

verifierRouter.use('/public/definitions/presentation-request/:presentation_definition_id', async (req, res) => {

	const presentation_definition_id = req.params.presentation_definition_id;


	if (!presentation_definition_id) {
		return res.render('error', {
			msg: "No presentation definition was selected",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}


	const presentationDefinition = JSON.parse(JSON.stringify(verifierConfiguration.getPresentationDefinitions().filter(pd => pd.id == presentation_definition_id)[0])) as any;
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
		let selectedFieldPaths = req.body.fields;
		if (!Array.isArray(selectedFieldPaths)) {
			selectedFieldPaths = [selectedFieldPaths];
		}
		const selectedPaths = new Set(selectedFieldPaths);
		console.log("Selectd paths", selectedPaths);
		// Filter existing paths to keep only those selected by the user and update presentationDefinition
		const availableFields = presentationDefinition.input_descriptors[0].constraints.fields;
		console.log("Available fields = ", availableFields)
		const filteredFields = presentationDefinition.input_descriptors[0].constraints.fields.filter((field: any) =>
			selectedPaths.has(field.path[0])
		);

		console.log("filtered fields = ", filteredFields)
		presentationDefinition.input_descriptors[0].constraints.fields = filteredFields;
	}
	else if (req.method === "POST" && req.body.action && req.cookies.session_id) { // handle click of "open with..." button
		console.log("Cookie = ", req.cookies)

		// update is_cross_device --> false since the button was pressed
		await AppDataSource.getRepository(RelyingPartyState).createQueryBuilder("rp_state")
			.update({ is_cross_device: false })
			.where("session_id = :session_id", { session_id: req.cookies.session_id })
			.execute();
		return res.redirect(req.body.action);
	}

	const newSessionId = generateRandomIdentifier(12);
	addSessionIdCookieToResponse(res, newSessionId); // start session here
	console.log("call")
	const { url } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({ req, res }, presentationDefinition, newSessionId, config.url + "/verifier/callback");
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