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
import Ajv from 'ajv';
const ajv = new Ajv();

const presentationDefinitionSchema = {
  type: "object",
  required: ["id", "input_descriptors"],
  properties: {
    id: { type: "string" },
    input_descriptors: {
      type: "array",
      items: {
        type: "object",
        required: ["id", "constraints"],
        properties: {
          id: { type: "string" },
          constraints: {
            type: "object",
            required: ["fields"],
            properties: {
              fields: {
                type: "array",
                items: {
                  type: "object",
                  required: ["path"],
                  properties: {
                    path: {
                      type: "array",
                      items: { type: "string" }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
};

export const sanitizeInput = (input: string): string =>
	input.replace(/[^\x20-\x7E\n]/g, '');

export enum CredentialFormat {
	VC_SD_JWT = "vc+sd-jwt",
	JWT_VC_JSON = "jwt_vc_json"
}

const MAX_CERT_LENGTH = 5000;

const verifierRouter = Router();
// const verifiablePresentationRepository: Repository<VerifiablePresentationEntity> = AppDataSource.getRepository(VerifiablePresentationEntity);
const verifierConfiguration = appContainer.get<VerifierConfigurationInterface>(TYPES.VerifierConfigurationServiceInterface);
const openidForPresentationReceivingService = appContainer.get<OpenidForPresentationsReceivingInterface>(TYPES.OpenidForPresentationsReceivingService);

verifierRouter.get('/certificates', async (req, res) => {
	return res.render('verifier/certificates.pug', {
		lang: req.lang,
		locale: locale[req.lang],
		trustedRootCertificates: config.trustedRootCertificates
	})
})

verifierRouter.get('/import-certificate', async (req, res) => {
	return res.render('verifier/import_certificate.pug', {
		lang: req.lang,
		locale: locale[req.lang]
	})
})

verifierRouter.post('/import-certificate', async (req, res) => {
	const { certificate } = req.body;
	try {
		if (!certificate) {
			throw new Error("No certificate provided");
		}
		if (certificate.length > MAX_CERT_LENGTH) {
			throw new Error("Certificate too large");
		}
		if (!/^([A-Za-z0-9+/=\s-]+)$/.test(certificate)) {
			throw new Error("Invalid characters in certificate input");
		}
		const sanitizedCert = sanitizeInput(certificate);
		const pem = sanitizedCert.includes('-----BEGIN CERTIFICATE-----')
			? sanitizedCert
			: `-----BEGIN CERTIFICATE-----\n${sanitizedCert.trim()}\n-----END CERTIFICATE-----`;

		const normalizedPem = pem.replace(/\r\n/g, '\n');
		(config.trustedRootCertificates as string[]).push(normalizedPem.trim());
		res.redirect('/verifier/import-certificate');
	} catch (error) {
		res.render('verifier/import_certificate.pug', {
			lang: req.lang,
			locale: locale[req.lang],
			error: {
				errorMessage: 'error adding x509 certificate'
			}
		});
	}
});

verifierRouter.get('/public/manage-certificates', async (req, res) => {
	return res.render('verifier/manage_certificates.pug', {
		lang: req.lang,
		locale: locale[req.lang]
	})
})

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
		const { credentialParsingEngine } = await initializeCredentialEngine();
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


verifierRouter.use('/public/definitions/configurable-presentation-request/:presentation_definition_id', async (req, res) => {
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
	return res.render('verifier/configurable_presentation', {
		presentationDefinitionId: presentationDefinition.id,
		presentationDefinitionDescriptorId: presentationDefinition.input_descriptors[0].id,
		selectableFields,
		lang: req.lang,
		locale: locale[req.lang],
	});
})

verifierRouter.get('/public/definitions/edit-presentation-definition', async (req, res) => {
	return res.render('verifier/edit_presentation_definition', {
		lang: req.lang,
		locale: locale[req.lang],
	});
})

verifierRouter.post('/public/definitions/edit-presentation-definition', async (req, res) => {
	if (req.method === "POST" && req.body.action && req.cookies.session_id) {
		// update is_cross_device --> false since the button was pressed
		await AppDataSource.getRepository(RelyingPartyState).createQueryBuilder("rp_state")
			.update({ is_cross_device: false })
			.where("session_id = :session_id", { session_id: req.cookies.session_id })
			.execute();
		return res.redirect(req.body.action);
	}
	let presentationDefinition;
	try {
		presentationDefinition = JSON.parse(req.body.presentationDefinition);
		const validate = ajv.compile(presentationDefinitionSchema);
		if (!validate(presentationDefinition)) {
			return res.render('error.pug', {
				msg: "Invalid presentation definition format",
				code: 0,
				lang: req.lang,
				locale: locale[req.lang],
			});
		}
	} catch (error) {
		return res.render('error.pug', {
			msg: "Error while parsing the presentation definition",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang],
		})
	}
	const scheme = req.body.scheme

	const newSessionId = generateRandomIdentifier(12);
	addSessionIdCookieToResponse(res, newSessionId);
	const { url } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({ req, res }, presentationDefinition, newSessionId, config.url + "/verifier/callback");
	const modifiedUrl = url.toString().replace("openid4vp://cb", scheme)
	let authorizationRequestQR = await new Promise((resolve) => {
		qrcode.toDataURL(modifiedUrl.toString(), {
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
		wwwalletURL: config.wwwalletURL,
		authorizationRequestURL: modifiedUrl,
		authorizationRequestQR,
		presentationDefinition: JSON.stringify(JSON.parse(req.body.presentationDefinition)),
		state: url.searchParams.get('state'),
		lang: req.lang,
		locale: locale[req.lang],
	})
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
	let scheme = "openid4vp://cb";
	// If there are selected fields from a POST request, update the constraints accordingly
	if (req.method === "POST" && req.body.attributes) {
		let selectedFieldPaths = req.body.attributes;
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
		// Determine the presentation format based on the 'type' (sd-jwt or mdoc) provided by the form
		const selectedType = req.body.type // Default to sd-jwt if type is not provided
		if (selectedType === "sd-jwt") {
			presentationDefinition.input_descriptors[0].format = {
				"vc+sd-jwt": {
					"sd-jwt_alg_values": ["ES256"],
					"kb-jwt_alg_values": ["ES256"]
				},
			};
		} else if (selectedType === "mdoc") {
			presentationDefinition.input_descriptors[0].format = {
				"mso_mdoc": {
					"sd-jwt_alg_values": ["ES256"],
					"kb-jwt_alg_values": ["ES256"]
				},
			};
		}
		presentationDefinition.input_descriptors[0].purpose = req.body.purpose
		presentationDefinition.input_descriptors[0].id = req.body.descriptorId
		scheme = req.body.scheme
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
	const { url } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({ req, res }, presentationDefinition, newSessionId, config.url + "/verifier/callback");
	const modifiedUrl = url.toString().replace("openid4vp://cb", scheme)
	let authorizationRequestQR = await new Promise((resolve) => {
		qrcode.toDataURL(modifiedUrl.toString(), {
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
		wwwalletURL: config.wwwalletURL,
		authorizationRequestURL: modifiedUrl,
		authorizationRequestQR,
		presentationDefinition: JSON.stringify(presentationDefinition),
		state: url.searchParams.get('state'),
		lang: req.lang,
		locale: locale[req.lang],
	})


})


export { verifierRouter };