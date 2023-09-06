import { Router } from "express";
import { verifierPanelAuthChain } from "../configuration/authentication/authenticationChain";
import locale from "../locale";
import { Repository } from "typeorm";
import AppDataSource from "../AppDataSource";
import { VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
import { appContainer } from "../services/inversify.config";
import { TYPES } from "../services/types";
import { VerifierConfigurationInterface } from "../services/interfaces";



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

export { verifierRouter };