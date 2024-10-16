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
import crypto from 'node:crypto';
import {
	HasherAlgorithm,
	HasherAndAlgorithm,
	SdJwt,
} from '@sd-jwt/core'

import axios from 'axios';
import base64url from "base64url";
import { generateDataUriFromSvg } from "../lib/generateDataUriFromSvg";
import { generateRandomIdentifier } from "../lib/generateRandomIdentifier";
import { addSessionIdCookieToResponse } from "../sessionIdCookieConfig";


export enum CredentialFormat {
	VC_SD_JWT = "vc+sd-jwt",
	JWT_VC_JSON = "jwt_vc_json"
}

// const encoder = new TextEncoder();

const defaultLocale = 'en-US';

// Encoding the string into a Uint8Array
const hasherAndAlgorithm: HasherAndAlgorithm = {
	hasher: (input: string) => {
		// return crypto.subtle.digest('SHA-256', encoder.encode(input)).then((v) => new Uint8Array(v));
		return new Promise((resolve, _reject) => {
			const hash = crypto.createHash('sha256');
			hash.update(input);
			resolve(new Uint8Array(hash.digest()));
	});
	},
	algorithm: HasherAlgorithm.Sha256
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
	const result = await openidForPresentationReceivingService.getPresentationBySessionId({ req, res });
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
	const result = await openidForPresentationReceivingService.getPresentationBySessionId({ req, res });
	 
	console.log("Callback Result = ", result)
	if (result.status == false || 
			result.rpState.vp_token == null ||
			result.rpState.claims == null ||
			result.rpState.date_created == null) {
		return res.render('error.pug', {
			msg: "Failed to get presentation",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang],
		})
	}
	
	const { vp_token, claims, date_created } = result.rpState;
	const status = result.status;

	const credentialImages = [];

	const credentialPayloads = []
	if (vp_token.includes('~')) {
		const parsedCredential = await SdJwt.fromCompact<Record<string, unknown>, any>(vp_token)
			.withHasher(hasherAndAlgorithm)
			.getPrettyClaims();
		const sdJwtHeader = JSON.parse(base64url.decode(vp_token.split('.')[0])) as any;
		credentialPayloads.push(parsedCredential);
		console.log("Parsed credential = ", parsedCredential)
		const credentialIssuerMetadata = await axios.get(parsedCredential.iss + "/.well-known/openid-credential-issuer").catch(() => null);
		if (!credentialIssuerMetadata) {
			console.error("Couldnt get image for the credential " + vp_token);
			return res.status(400).send({ error: "Insufficient metadata" })
		}
		console.log("Credential issuer metadata = ", credentialIssuerMetadata.data)
		const fistImageUri = Object.values(credentialIssuerMetadata.data.credential_configurations_supported).map((conf: any) => {
			if (conf?.vct == parsedCredential?.vct) {
				return conf?.display[0] ? conf?.display[0]?.background_image?.uri : undefined;
			}
			return undefined;
		}).filter((val) => val)[0];

		if (sdJwtHeader?.vctm && sdJwtHeader?.vctm?.display.length > 0 && sdJwtHeader?.vctm?.display[0][defaultLocale]?.rendering?.svg_templates.length > 0 && sdJwtHeader?.vctm?.display[0][defaultLocale]?.rendering?.svg_templates[0]?.uri) {
			const response = await axios.get(sdJwtHeader?.vctm?.display[0][defaultLocale].rendering.svg_templates[0].uri);
			const svgText = response.data;
			const pathsWithValues: any[] = []; 
			const dataUri = generateDataUriFromSvg(svgText, pathsWithValues); // replaces all with empty string
			credentialImages.push(dataUri);
		}
		else if(sdJwtHeader?.vctm && sdJwtHeader?.vctm?.display.length > 0 && sdJwtHeader?.vctm?.display[0][defaultLocale]?.rendering?.simple?.logo?.uri) {
			credentialImages.push(sdJwtHeader?.vctm?.display[0][defaultLocale]?.rendering?.simple?.logo?.uri);
		}
		else if (fistImageUri) {
			credentialImages.push(fistImageUri);
		}
		else {
			console.error("Not supported format. Parsing failed")
			return res.status(400).send({ error: "Not supoorted format" })	
		}
	}
	else {
		console.error("Not supported format. Parsing failed")
		return res.status(400).send({ error: "Not supoorted format" })
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
	console.log("FIELDS = ", req.body.fields)
	if (req.cookies['session_id'] && req.method == "POST") {
		const { status } = await openidForPresentationReceivingService.getPresentationBySessionId({ req, res });
		if (status == true) {
			return res.send({ url: `/verifier/callback` });
		}
		else {
			return res.send({ });
		}
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

	const newSessionId = generateRandomIdentifier(12);
	addSessionIdCookieToResponse(res, newSessionId); // start session here
	console.log("call")
	const { url } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({req, res}, presentationDefinition, newSessionId, config.url + "/verifier/callback");	
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