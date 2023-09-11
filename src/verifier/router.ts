import { Router } from "express";
import { verifierPanelAuthChain } from "../configuration/authentication/authenticationChain";
import { Repository } from "typeorm";
import AppDataSource from "../AppDataSource";
import { VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
import { appContainer } from "../services/inversify.config";
import { TYPES } from "../services/types";
import { VerifierConfigurationInterface } from "../services/interfaces";
import base64url from "base64url";
import locale from "../configuration/locale";
import { VerifierConfigurationService } from "../configuration/verifier/VerifierConfigurationService";
import { PresentationSubmission } from "@gunet/ssi-sdk";
import { JSONPath } from "jsonpath-plus";



const verifierRouter = Router();
const verifiablePresentationRepository: Repository<VerifiablePresentationEntity> = AppDataSource.getRepository(VerifiablePresentationEntity);
const verifierConfiguration = appContainer.get<VerifierConfigurationInterface>(TYPES.VerifierConfigurationServiceInterface);


verifierPanelAuthChain.components.map(c => {
	verifierRouter.use(async (req, res, next) => {
		c.authenticate(req, res, next)
	});
})


verifierRouter.get('/', async (req, res) => {
	
	return res.render('verifier/definitions.pug', {
		lang: req.lang,
		presentationDefinitions: verifierConfiguration.getPresentationDefinitions(),
		locale: locale[req.lang]
	})
})


verifierRouter.get('/filter/by/definition/:definition_id', async (req, res) => {
	const definition_id = req.params.definition_id;
	if (!definition_id) {
		return res.status(500).send({ error: "No definition id was specified" });
	}
	const verifiablePresentations = await verifiablePresentationRepository.createQueryBuilder('vp')
		.where("vp.presentation_definition_id = :definition_id", { definition_id: definition_id })
		.getMany();
	return res.render('verifier/presentations.pug', {
		lang: req.lang,
		verifiablePresentations: verifiablePresentations,
		locale: locale[req.lang]
	})
})



type PresentationView = {
	descriptor_mapped_value: {
		inputDescriptorId: string;
		vcView: VerifiableCredentialView;
	}[]
}

type VerifiableCredentialView = {
	rows: {
		name: string;
		value: string;
	}[];
}


verifierRouter.get('/presentation/:presentation_id', async (req, res) => {
	const presentation_id = req.params.presentation_id;
	if (!presentation_id) {
		return res.status(500).send({ error: "No presentation_id was specified" });
	}
	const verifiablePresentation = await verifiablePresentationRepository.createQueryBuilder('vp')
		.where("vp.id = :presentation_id", { presentation_id: presentation_id })
		.getOne();
	
	if (!verifiablePresentation || !verifiablePresentation.raw_presentation) {
		return res.status(400).render('error', {
			msg: "Verifiable presentation not found",
			lang: req.lang,
			locale: locale[req.lang]
		});
	}

	const presentationSubmission = verifiablePresentation.presentation_submission as PresentationSubmission;

	const payload = JSON.parse(base64url.decode(verifiablePresentation.raw_presentation?.split('.')[1])) as any;
	const vcList = payload.vp.verifiableCredential as string[];
	const credentialList = [];
	for (const vc of vcList) {
		const vcPayload = JSON.parse(base64url.decode(vc.split('.')[1])) as any;
		credentialList.push(vcPayload.vc);
	}

	const presentationDefinition = appContainer.resolve(VerifierConfigurationService)
		.getPresentationDefinitions()
		.filter(pd => 
			pd.id == verifiablePresentation.presentation_definition_id
		)[0];

	let view: PresentationView = { descriptor_mapped_value: [] };
	for (const descriptor of presentationDefinition.input_descriptors) {
		const correspondingElementOnSubmission = presentationSubmission.descriptor_map.filter(desc => desc.id == descriptor.id)[0];

		const vcRows = descriptor.constraints.fields.map((field) => {
			const vcPath = correspondingElementOnSubmission.path;
			const payload = JSON.parse(base64url.decode(verifiablePresentation.raw_presentation?.split('.')[1] as string)) as any;
			const vcJwtString = JSONPath({ json: payload.vp, path: vcPath })[0];
			const vcPayload = JSON.parse(base64url.decode(vcJwtString.split('.')[1])) as any;
			const valuePath = field.path[0];
			const value = JSONPath({ json: vcPayload.vc, path: valuePath })[0] as string;
			return { name: valuePath, value: value }
		});
		view.descriptor_mapped_value.push({
			inputDescriptorId: descriptor.id,
			vcView: { rows: vcRows }
		});
	}
	console.dir(view, { depth: null })
	return res.render('verifier/detailed-presentation.pug', {
		view: view,
		status: verifiablePresentation.status,
		lang: req.lang,
		locale: locale[req.lang]
	})
})

export { verifierRouter };