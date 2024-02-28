import { Container } from "inversify";
import { OpenidForPresentationsReceivingInterface, OpenidForCredentialIssuingAuthorizationServerInterface, VerifierConfigurationInterface, CredentialIssuersConfiguration, DidKeyResolverServiceInterface } from "./interfaces";
import { TYPES } from "./types";
import { OpenidForPresentationsReceivingService } from "./OpenidForPresentationReceivingService";
import 'reflect-metadata';
import { OpenidForCredentialIssuingAuthorizationServerService } from "./OpenidForCredentialIssuingAuthorizationServerService";
import { CredentialIssuersConfigurationService } from "../configuration/CredentialIssuersConfigurationService";
import { CredentialIssuersService } from "./CredentialIssuersService";
import { ExpressAppService } from "./ExpressAppService";
import { VerifierConfigurationService } from "../configuration/verifier/VerifierConfigurationService";
import { DidKeyResolverService } from "./DidKeyResolverService";


const appContainer = new Container();

// to add a new configuration, unbind this with appContainer.unbind() if from external component
appContainer.bind<VerifierConfigurationInterface>(TYPES.VerifierConfigurationServiceInterface)
	.to(VerifierConfigurationService);


// to add a new configuration, unbind this with appContainer.unbind() if from external component
appContainer.bind<CredentialIssuersConfiguration>(TYPES.CredentialIssuersConfiguration)
	.to(CredentialIssuersConfigurationService);


appContainer.bind<OpenidForPresentationsReceivingInterface>(TYPES.OpenidForPresentationsReceivingService)
	.to(OpenidForPresentationsReceivingService);


appContainer.bind<OpenidForCredentialIssuingAuthorizationServerInterface>(TYPES.OpenidForCredentialIssuingAuthorizationServerService)
	.to(OpenidForCredentialIssuingAuthorizationServerService);



appContainer.bind<CredentialIssuersService>(TYPES.CredentialIssuersService)
	.to(CredentialIssuersService);

appContainer.bind<ExpressAppService>(TYPES.ExpressAppService)
	.to(ExpressAppService);


appContainer.bind<DidKeyResolverServiceInterface>(TYPES.DidKeyResolverService)
	.to(DidKeyResolverService);

export { appContainer }