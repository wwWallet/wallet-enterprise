import { CategorizedRawCredential, CategorizedRawCredentialView } from "../openid4vci/Metadata";





type CredentialView = {
	credential_id: string;
	credential_logo_url: string;
	credentialSubject: any; // defines the structure of the viewed credential
	data: CategorizedRawCredential<any>;
	view: CategorizedRawCredentialView;
}
export { CredentialView }