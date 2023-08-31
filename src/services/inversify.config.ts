import { Container } from "inversify";
import { OpenidForPresentationsReceivingInterface, WalletKeystore, CredentialPool, VerifierConfigurationInterface, CredentialReceiving, OpenidForCredentialIssuingAuthorizationServerInterface } from "./interfaces";
import { TYPES } from "./types";
import { FilesystemKeystoreService } from "./FilesystemKeystoreService";
import { OpenidForPresentationsReceivingService } from "./OpenidForPresentationReceivingService";
import 'reflect-metadata';
import { CredentialPoolService } from "./CredentialPoolService";
import { CredentialReceivingService } from "./CredentialReceivingService";
import { OpenidForCredentialIssuingAuthorizationServerService } from "./OpenidForCredentialIssuingAuthorizationServerService";
import { CredentialIssuersConfigurationService } from "../configuration/CredentialIssuersConfigurationService";
import { CredentialIssuersService } from "./CredentialIssuersService";
import { ExpressAppService } from "./ExpressAppService";
import { VerifierConfigurationV2Service } from "../configuration/verifier/VerifierConfigurationV2Service";


const appContainer = new Container();

// to add a new configuration, unbind this with appContainer.unbind() if from external component
appContainer.bind<VerifierConfigurationInterface>(TYPES.VerifierConfigurationServiceInterface)
	.to(VerifierConfigurationV2Service);

// to add a new configuration, unbind this with appContainer.unbind() if from external component
appContainer.bind<CredentialIssuersConfigurationService>(TYPES.CredentialIssuersConfigurationService)
	.to(CredentialIssuersConfigurationService);


appContainer.bind<WalletKeystore>(TYPES.FilesystemKeystoreService)
	.to(FilesystemKeystoreService);

appContainer.bind<OpenidForPresentationsReceivingInterface>(TYPES.OpenidForPresentationsReceivingService)
	.to(OpenidForPresentationsReceivingService);


appContainer.bind<OpenidForCredentialIssuingAuthorizationServerInterface>(TYPES.OpenidForCredentialIssuingAuthorizationServerService)
	.to(OpenidForCredentialIssuingAuthorizationServerService);


appContainer.bind<CredentialPool>(TYPES.CredentialPoolService)
	.to(CredentialPoolService);


appContainer.bind<CredentialReceiving>(TYPES.CredentialReceivingService)
	.to(CredentialReceivingService);

appContainer.bind<CredentialIssuersService>(TYPES.CredentialIssuersService)
	.to(CredentialIssuersService);

appContainer.bind<ExpressAppService>(TYPES.ExpressAppService)
	.to(ExpressAppService);

export { appContainer }