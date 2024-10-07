import { CategorizedRawCredentialView } from "../openid4vci/Metadata";

export type CredentialView = {
	credential_id: string,
	credential_supported_object: any;
	view: CategorizedRawCredentialView;
	deferredFlow: boolean;
}
