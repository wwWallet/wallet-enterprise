import { VerifierConfigurationService } from "../../configuration/verifier/VerifierConfigurationService";
import { OpenidForCredentialIssuingAuthorizationServerService } from "../OpenidForCredentialIssuingAuthorizationServerService";
import { OpenidForPresentationsReceivingService } from "../OpenidForPresentationReceivingService";
import { CredentialConfigurationRegistry, CredentialDataModelRegistry } from "../interfaces";
import { appContainer } from "../inversify.config";
import { TYPES } from "../types";


export const openidForCredentialIssuingAuthorizationServerService = appContainer.resolve(OpenidForCredentialIssuingAuthorizationServerService);
export const openidForPresentationReceivingService = appContainer.resolve(OpenidForPresentationsReceivingService);
export const verifierConfigurationService = appContainer.resolve(VerifierConfigurationService);
export const credentialConfigurationRegistryService: CredentialConfigurationRegistry = appContainer.get(TYPES.CredentialConfigurationRegistryService)
export const credentialDataModelRegistryService: CredentialDataModelRegistry = appContainer.get(TYPES.CredentialDataModelRegistry);
