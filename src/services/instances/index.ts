import { CredentialPoolService } from "../CredentialPoolService";
import { FilesystemKeystoreService } from "../FilesystemKeystoreService";
import { OpenidForCredentialIssuingAuthorizationServerService } from "../OpenidForCredentialIssuingAuthorizationServerService";
import { OpenidForPresentationsReceivingService } from "../OpenidForPresentationReceivingService";
import { appContainer } from "../inversify.config";


export const openidForCredentialIssuingAuthorizationServerService = appContainer.resolve(OpenidForCredentialIssuingAuthorizationServerService);
export const openidForPresentationReceivingService = appContainer.resolve(OpenidForPresentationsReceivingService);
export const credentialPoolService = appContainer.resolve(CredentialPoolService);
export const keystoreService = appContainer.resolve(FilesystemKeystoreService);