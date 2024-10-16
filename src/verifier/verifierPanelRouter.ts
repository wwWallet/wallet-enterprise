import { Router } from "express";
import { verifierPanelAuthChain } from "../configuration/authentication/authenticationChain";
import { Repository } from "typeorm";
import AppDataSource from "../AppDataSource";
import { appContainer } from "../services/inversify.config";
import { TYPES } from "../services/types";
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "../services/interfaces";
import base64url from "base64url";
import locale from "../configuration/locale";
import { RelyingPartyState } from "../entities/RelyingPartyState.entity";

const openidForPresentationReceivingService = appContainer.get<OpenidForPresentationsReceivingInterface>(TYPES.OpenidForPresentationsReceivingService);


const verifierPanelRouter = Router();
const rpStateRepository: Repository<RelyingPartyState> = AppDataSource.getRepository(RelyingPartyState);
const verifierConfiguration = appContainer.get<VerifierConfigurationInterface>(TYPES.VerifierConfigurationServiceInterface);


verifierPanelAuthChain.components.map(c => {
	verifierPanelRouter.use(async (req, res, next) => {
		c.authenticate(req, res, next)
	});
})


verifierPanelRouter.get('/', async (req, res) => {
	
	return res.render('verifier/definitions.pug', {
		lang: req.lang,
		presentationDefinitions: verifierConfiguration.getPresentationDefinitions(),
		locale: locale[req.lang]
	})
})

type VerifiablePresentationWithDetails = RelyingPartyState & { holderInfo?: string, claims?: any };

verifierPanelRouter.get('/filter/by/definition/:definition_id', async (req, res) => {
	const definition_id = req.params.definition_id;
	if (!definition_id) {
		return res.status(500).send({ error: "No definition id was specified" });
	}
	let verifiablePresentations = await rpStateRepository.createQueryBuilder()
		.where("presentation_definition_id = :definition_id", { definition_id: definition_id })
		.getMany();

	const presentationsWithDetails: VerifiablePresentationWithDetails[] = verifiablePresentations.map(vp => {
		try {
			const decoded = vp.vp_token ? JSON.parse(base64url.decode(vp.vp_token.split('.')[1])) : null as any;
			const holderInfo = decoded?.vp?.holder || "No Holder Info";
			const claims = vp.claims;
			return { ...vp, holderInfo, claims } as VerifiablePresentationWithDetails;
		} catch (error) {
			console.error("Error decoding VP:", error);
			return { ...vp, holderInfo: 'Error decoding holder info' } as VerifiablePresentationWithDetails;
		}
	});

	return res.render('verifier/presentations.pug', {
		lang: req.lang,
		verifiablePresentations: presentationsWithDetails,
		locale: locale[req.lang]
	})
})


verifierPanelRouter.get('/presentation/:presentation_id', async (req, res) => {
	const presentation_id = req.params.presentation_id;
	if (!presentation_id) {
		return res.status(500).send({ error: "No presentation_id was specified" });
	}
	const { presentationClaims, rawPresentation } = await openidForPresentationReceivingService.getPresentationById(presentation_id as string);

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

	return res.render('verifier/detailed-presentation.pug', {
		lang: req.lang,
		presentationClaims: presentationClaims,
		credentialPayloads: credentials,
		locale: locale[req.lang],
	})
})

export { verifierPanelRouter };