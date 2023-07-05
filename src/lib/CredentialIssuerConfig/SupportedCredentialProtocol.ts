import { UserSession } from "../../RedisModule";
import { CategorizedRawCredential } from "../../openid4vci/Metadata";
import { VerifiableCredentialFormat, Display, CredentialSupported } from "../../types/oid4vci";
import { CredentialIssuerConfig } from "./CredentialIssuerConfig";

export interface SupportedCredentialProtocol {
	getCredentialIssuerConfig(): CredentialIssuerConfig;
	getId(): string;
	getFormat(): VerifiableCredentialFormat;
	getTypes(): string[];
	getDisplay(): Display;

	getResources(userSession: UserSession): Promise<CategorizedRawCredential<any>[]>;
	signCredential(userSession: UserSession, holderDID: string): Promise<{ format: VerifiableCredentialFormat, credential: any }>;

	exportCredentialSupportedObject(): CredentialSupported;
}
