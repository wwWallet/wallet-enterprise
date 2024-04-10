import { VerifierConfigurationService } from "../../configuration/verifier/VerifierConfigurationService";
import { OpenidForCredentialIssuingAuthorizationServerService } from "../OpenidForCredentialIssuingAuthorizationServerService";
import { OpenidForPresentationsReceivingService } from "../OpenidForPresentationReceivingService";
import { appContainer } from "../inversify.config";


export const openidForCredentialIssuingAuthorizationServerService = appContainer.resolve(OpenidForCredentialIssuingAuthorizationServerService);
export const openidForPresentationReceivingService = appContainer.resolve(OpenidForPresentationsReceivingService);
export const verifierConfigurationService = appContainer.resolve(VerifierConfigurationService);