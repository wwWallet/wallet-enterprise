import { Container } from "inversify";
import { OpenidForPresentationsReceivingInterface, WalletKeystore, CredentialReceiving, OpenidForCredentialIssuingAuthorizationServerInterface, DidKeyResolverService, VerifierConfigurationInterface, CredentialIssuersConfiguration } from "./interfaces";
import { TYPES } from "./types";
import { FilesystemKeystoreService } from "./FilesystemKeystoreService";
import { OpenidForPresentationsReceivingService } from "./OpenidForPresentationReceivingService";
import 'reflect-metadata';
import { CredentialReceivingService } from "./CredentialReceivingService";
import { OpenidForCredentialIssuingAuthorizationServerService } from "./OpenidForCredentialIssuingAuthorizationServerService";
import { CredentialIssuersConfigurationService } from "../configuration/CredentialIssuersConfigurationService";
import { CredentialIssuersService } from "./CredentialIssuersService";
import { ExpressAppService } from "./ExpressAppService";
import { W3CDidKeyResolverService } from "./W3CDidKeyResolverService";
import { DidKeyMethodVersion, didKeyMethodVersion } from "../configuration/didKeyMethodVersion";
import { EBSIDidKeyResolverService } from "./EBSIDidKeyResolverService";
import { VerifierConfigurationService } from "../configuration/verifier/VerifierConfigurationService";


const appContainer = new Container();

// to add a new configuration, unbind this with appContainer.unbind() if from external component
appContainer.bind<VerifierConfigurationInterface>(TYPES.VerifierConfigurationServiceInterface)
	.to(VerifierConfigurationService);


// to add a new configuration, unbind this with appContainer.unbind() if from external component
appContainer.bind<CredentialIssuersConfiguration>(TYPES.CredentialIssuersConfiguration)
	.to(CredentialIssuersConfigurationService);


appContainer.bind<WalletKeystore>(TYPES.FilesystemKeystoreService)
	.to(FilesystemKeystoreService);

appContainer.bind<OpenidForPresentationsReceivingInterface>(TYPES.OpenidForPresentationsReceivingService)
	.to(OpenidForPresentationsReceivingService);


appContainer.bind<OpenidForCredentialIssuingAuthorizationServerInterface>(TYPES.OpenidForCredentialIssuingAuthorizationServerService)
	.to(OpenidForCredentialIssuingAuthorizationServerService);




appContainer.bind<CredentialReceiving>(TYPES.CredentialReceivingService)
	.to(CredentialReceivingService);

appContainer.bind<CredentialIssuersService>(TYPES.CredentialIssuersService)
	.to(CredentialIssuersService);

appContainer.bind<ExpressAppService>(TYPES.ExpressAppService)
	.to(ExpressAppService);


switch (didKeyMethodVersion) {
	case DidKeyMethodVersion.W3C:
		appContainer.bind<DidKeyResolverService>(TYPES.DidKeyResolverService)
			.to(W3CDidKeyResolverService);
		break;
	case DidKeyMethodVersion.EBSI:
		appContainer.bind<DidKeyResolverService>(TYPES.DidKeyResolverService)
			.to(EBSIDidKeyResolverService);
		break;
	default:
		appContainer.bind<DidKeyResolverService>(TYPES.DidKeyResolverService)
			.to(W3CDidKeyResolverService);
		break;
}

export { appContainer }