import { Container } from "inversify";
import { OpenidForPresentationsReceivingInterface, WalletKeystore, OpenidForCredentialIssuingInterface, CredentialPool, VerifierConfigurationInterface, CredentialReceiving } from "./interfaces";
import { TYPES } from "./types";
import { FilesystemKeystoreService } from "./FilesystemKeystoreService";
import { OpenidForPresentationsReceivingService } from "./OpenidForPresentationReceivingService";
import { VerifierConfigurationService } from "../configuration/verifier/VerifierConfigurationService";
import { OpenidForCredentialIssuingService } from "./OpenidForCredentialIssuingService";
import 'reflect-metadata';
import { CredentialPoolService } from "./CredentialPoolService";
import { CredentialReceivingService } from "./CredentialReceivingService";


const appContainer = new Container();

// to add a new configuration, unbind this with appContainer.unbind() if from external component
appContainer.bind<VerifierConfigurationInterface>(TYPES.VerifierConfigurationServiceInterface)
	.to(VerifierConfigurationService);

appContainer.bind<WalletKeystore>(TYPES.FilesystemKeystoreService)
	.to(FilesystemKeystoreService);

appContainer.bind<OpenidForPresentationsReceivingInterface>(TYPES.OpenidForPresentationsReceivingService)
	.to(OpenidForPresentationsReceivingService);


appContainer.bind<OpenidForCredentialIssuingInterface>(TYPES.OpenidForCredentialIssuingService)
	.to(OpenidForCredentialIssuingService);


appContainer.bind<CredentialPool>(TYPES.CredentialPoolService)
	.to(CredentialPoolService);


appContainer.bind<CredentialReceiving>(TYPES.CredentialReceivingService)
	.to(CredentialReceivingService);		
	
export { appContainer }