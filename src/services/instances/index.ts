import { OpenidForCredentialIssuingService } from "../OpenidForCredentialIssuingService";
import { OpenidForPresentationsReceivingService } from "../OpenidForPresentationReceivingService";
import { appContainer } from "../inversify.config";


export const openidForCredentialIssuingService = appContainer.resolve(OpenidForCredentialIssuingService);
export const openidForPresentationReceivingService = appContainer.resolve(OpenidForPresentationsReceivingService);