import { Router } from "express";
import { consent } from "./consentPage";
import { credentialConfigurationRegistryService } from "../services/instances";
import { credentialConfigurationRegistryServiceEmitter } from "../services/CredentialConfigurationRegistryService";

const authorizationRouter = Router();

function registerAuthChains() {
	credentialConfigurationRegistryService.getAllRegisteredCredentialConfigurations().map((conf) => {
		const authChain = conf.getAuthenticationChain();
		authChain.components.map(c => {
			console.log("Registering authentication component: ", c.identifier)
			authorizationRouter.use(async (req, res, next) => {
				c.authenticate(req, res, next)
			});
		})
	});
}

credentialConfigurationRegistryServiceEmitter.on('initialized', () => {
	registerAuthChains();
	authorizationRouter.use('/consent', consent);
});


export { authorizationRouter };