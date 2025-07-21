import { Router } from "express";
import { consent } from "./consentPage";
import { credentialConfigurationRegistryService } from "../services/instances";
import { credentialConfigurationRegistryServiceEmitter } from "../services/CredentialConfigurationRegistryService";

const authorizationRouter = Router();

authorizationRouter.use((req, res, next) => {
	const originalRender = res.render;

	console.log("Session: ", req.session, req.authorizationServerState)
	// @ts-ignore
	res.render = function (view, options = {}, callback: any) {
		const supportedCredentialType = credentialConfigurationRegistryService.getAllRegisteredCredentialConfigurations().filter((sc) => req.authorizationServerState && sc.getScope() === req.authorizationServerState.scope)[0];

		const extraData = { supportedCredentialType: supportedCredentialType ? supportedCredentialType.exportCredentialSupportedObject(): undefined };

		const finalOptions = { ...options, ...extraData };

		// @ts-ignore
		originalRender.call(res, view, finalOptions, callback);
	};

	next();
});

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
