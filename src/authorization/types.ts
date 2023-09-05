import { CategorizedRawCredentialView } from "../openid4vci/Metadata";
import { CredentialSupported } from "../types/oid4vci";





export type CredentialView = {
	credential_id: string,
	credential_supported_object: CredentialSupported;
	view: CategorizedRawCredentialView;
	deferredFlow: boolean;
}
