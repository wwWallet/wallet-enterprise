import { Router } from "express";
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

const dcqlQuerySchema = {
	type: "object",
	required: ["credentials"],
	properties: {
		credentials: {
			type: "array",
			items: {
				type: "object",
				required: ["id", "format"],
				properties: {
					id: { type: "string" },
					format: { type: "string" },
					meta: {
						type: "object",
						properties: {
							doctype_value: { type: "string" },
							"sd-jwt_alg_values": {
								type: "array",
								items: { type: "string" }
							},
							"kb-jwt_alg_values": {
								type: "array",
								items: { type: "string" }
							}
						},
						additionalProperties: true
					},
					claims: {
						type: "array",
						items: {
							type: "object",
							required: ["path"],
							properties: {
								id: { type: "string" },
								path: {
									type: "array",
									items: { type: "string" }
								},
								intent_to_retain: { type: "boolean" },
								filter: { type: "object" }
							}
						}
					}
				}
			}
		},
		credential_sets: {
			type: "array",
			items: {
				type: "object",
				required: ["options", "purpose"],
				properties: {
					options: {
						type: "array",
						items: {
							type: "array",
							items: { type: "string" }
						}
					},
					purpose: { type: "string" }
				}
			}
		}
	}
};

export const sanitizeInput = (input: string): string =>
	input.replace(/[^\x20-\x7E\n]/g, '');


const MAX_CERT_LENGTH = 5000;

const verifierRouter = Router();
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
	return res.render('verifier/import-certificate.pug', {
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
		res.render('verifier/import-certificate.pug', {
			lang: req.lang,
			locale: locale[req.lang],
			error: {
				errorMessage: 'error adding x509 certificate'
			}
		});
	}
});

verifierRouter.get('/public/manage-certificates', async (req, res) => {
	return res.render('verifier/manage-certificates.pug', {
		lang: req.lang,
		locale: locale[req.lang]
	})
})

verifierRouter.get('/public/definitions', async (req, res) => {

	return res.render('verifier/public-definitions.pug', {
		lang: req.lang,
		presentationRequests: verifierConfiguration.getPresentationRequests(),
		locale: locale[req.lang]
	})
})


verifierRouter.get('/callback/status', async (req, res) => { // response with the status of the presentation (this endpoint should be protected)
	if (!req.cookies['session_id']) {
		return res.send({ status: false, error: "Missing session_id from cookies" });
	}
	const result = await openidForPresentationReceivingService.getPresentationBySessionIdOrPresentationDuringIssuanceSession(req.cookies['session_id'], undefined, false);
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

	const result = await openidForPresentationReceivingService.getPresentationBySessionIdOrPresentationDuringIssuanceSession(session_id, undefined, true);

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
			let imageUri = undefined;
			try {
				const dataUriFn = result.value.metadata.credential.image?.dataUri;
				imageUri = dataUriFn ? await dataUriFn() : undefined;
			} catch (err) {
				console.warn('Failed to load credential image:', err);
			}
			credentialImages.push(imageUri);
			credentialPayloads.push(result.value.signedClaims);
		}
	}

	console.log("Presentation messages: ", result.presentationInfo);
	return res.render('verifier/success.pug', {
		lang: req.lang,
		locale: locale[req.lang],
		status: status,
		verificationTimestamp: date_created.toISOString(),
		presentationClaims: claims,
		credentialPayloads: credentialPayloads,
		presentationInfo: result.presentationInfo,
		credentialImages: credentialImages,
	})
})


verifierRouter.use('/public/definitions/configurable-presentation-request/:presentation_request_id', async (req, res) => {
	const presentation_request_id = req.params.presentation_request_id;
	if (!presentation_request_id) {
		return res.render('error', {
			msg: "No presentation definition was selected",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}
	const presentationRequest = verifierConfiguration.getPresentationRequests().filter(pd => pd.id == presentation_request_id)[0];
	if (!presentationRequest) {
		return res.render('error', {
			msg: "No presentation definition was found",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}
	const selectableFields = presentationRequest.dcql_query.credentials
		.flatMap((credential: any) => credential.claims)
		.map((claim: any) => {
				const label = claim.path.join(".");
				return [label, claim.path[0]];
		});
	return res.render('verifier/configurable-presentation', {
		presentationRequestId: presentationRequest.id,
		dcqlQuery: presentationRequest.dcql_query,
		selectableFields,
		lang: req.lang,
		locale: locale[req.lang],
	});
})

verifierRouter.get('/public/definitions/edit-dcql-query', async (req, res) => {
	return res.render('verifier/edit-dcql-query', {
		lang: req.lang,
		locale: locale[req.lang],
		schema: dcqlQuerySchema
	});
})

verifierRouter.post('/public/definitions/edit-dcql-query', async (req, res) => {
	if (req.method === "POST" && req.body.action && req.cookies.session_id) {
		// update is_cross_device --> false since the button was pressed
		await AppDataSource.getRepository(RelyingPartyState).createQueryBuilder("rp_state")
			.update({ is_cross_device: false })
			.where("session_id = :session_id", { session_id: req.cookies.session_id })
			.execute();
		return res.redirect(req.body.action);
	}
	let query;
	let presentationRequest = {}
	try {
		query = JSON.parse(req.body.dcqlQuery);
		const validate = ajv.compile(dcqlQuerySchema);
		if (!validate(query)) {
			return res.render('error.pug', {
				msg: "Invalid presentation definition format",
				code: 0,
				lang: req.lang,
				locale: locale[req.lang],
			});
		}
		presentationRequest = {
			id: "EditableDcqlQuery",
			title: "Editable DCQL Query",
			dcql_query: query
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
	const { url } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({ req, res }, presentationRequest, newSessionId, config.url + "/verifier/callback");
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
		presentationRequest: JSON.stringify(JSON.parse(req.body.dcqlQuery)),
		state: url.searchParams.get('state'),
		lang: req.lang,
		locale: locale[req.lang],
	})
})


verifierRouter.get('/public/definitions/presentation-request/status/:presentation_request_id', async (req, res) => {
	console.log("session_id : ", req.cookies['session_id'])
	if (req.cookies['session_id'] && req.method == "GET") {
		const { status } = await openidForPresentationReceivingService.getPresentationBySessionIdOrPresentationDuringIssuanceSession(req.cookies['session_id'], undefined, false);
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


verifierRouter.use('/public/definitions/presentation-request/:presentation_request_id', async (req, res) => {

	const presentation_request_id = req.params.presentation_request_id;


	if (!presentation_request_id) {
		return res.render('error', {
			msg: "No presentation request was selected",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}


	let presentationRequest;
	if (req.method === "POST" && req.body.dcql_query) {
		// Use the filtered query
		presentationRequest = { dcql_query: JSON.parse(req.body.dcql_query) };
	} else {
		presentationRequest = JSON.parse(JSON.stringify(verifierConfiguration.getPresentationRequests().filter(pd => pd.id == presentation_request_id)[0])) as any;
	}
	if (!presentationRequest) {
		return res.render('error', {
			msg: "No presentation request was found",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}

	let scheme = "openid4vp://cb";
	if (req.method === "POST" && req.body.scheme) {
		scheme = req.body.scheme;
	}

	if (req.method === "POST" && req.body.action && req.cookies.session_id) { // handle click of "open with..." button
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
	const { url } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({ req, res }, presentationRequest, newSessionId, config.url + "/verifier/callback");
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
		presentationRequest: JSON.stringify(presentationRequest.dcql_query),
		state: url.searchParams.get('state'),
		lang: req.lang,
		locale: locale[req.lang],
	})


})


export { verifierRouter };
