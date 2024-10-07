import { Container } from "inversify";
import { OpenidForPresentationsReceivingInterface, OpenidForCredentialIssuingAuthorizationServerInterface, VerifierConfigurationInterface, CredentialConfigurationRegistry, CredentialDataModelRegistry } from "./interfaces";
import { TYPES } from "./types";
import { OpenidForPresentationsReceivingService } from "./OpenidForPresentationReceivingService";
import 'reflect-metadata';
import { OpenidForCredentialIssuingAuthorizationServerService } from "./OpenidForCredentialIssuingAuthorizationServerService";
import { ExpressAppService } from "./ExpressAppService";
import { VerifierConfigurationService } from "../configuration/verifier/VerifierConfigurationService";
import { CredentialConfigurationRegistryService } from "./CredentialConfigurationRegistryService";
import { CredentialDataModelRegistryService } from "./CredentialDataModelRegistryService";


const appContainer = new Container();


appContainer.bind<CredentialConfigurationRegistry>(TYPES.CredentialConfigurationRegistryService)
	.to(CredentialConfigurationRegistryService).inSingletonScope();

// to add a new configuration, unbind this with appContainer.unbind() if from external component
appContainer.bind<VerifierConfigurationInterface>(TYPES.VerifierConfigurationServiceInterface)
	.to(VerifierConfigurationService);

appContainer.bind<OpenidForPresentationsReceivingInterface>(TYPES.OpenidForPresentationsReceivingService)
	.to(OpenidForPresentationsReceivingService);


appContainer.bind<OpenidForCredentialIssuingAuthorizationServerInterface>(TYPES.OpenidForCredentialIssuingAuthorizationServerService)
	.to(OpenidForCredentialIssuingAuthorizationServerService);


appContainer.bind<ExpressAppService>(TYPES.ExpressAppService)
	.to(ExpressAppService);

appContainer.bind<CredentialDataModelRegistry>(TYPES.CredentialDataModelRegistry)
	.to(CredentialDataModelRegistryService).inSingletonScope();


export { appContainer }