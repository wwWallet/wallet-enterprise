import { JWK } from "jose";
import { CredentialView } from "../../authorization/types";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { VerifiableCredentialFormat } from "wallet-common/dist/types";
import { CredentialSigner } from "../../services/interfaces";
import { Request } from "express";
import { AuthenticationChain } from "../../authentication/AuthenticationComponent";


export interface SupportedCredentialProtocol {

	getAuthenticationChain(): AuthenticationChain;

	getScope(): string;
	getCredentialSigner(): CredentialSigner;
	getId(): string;
	getFormat(): VerifiableCredentialFormat;
	getTypes(): string[];
	getDisplay(): any;

	getProfile(userSession: AuthorizationServerState): Promise<CredentialView | null>;
	generateCredentialResponse(userSession: AuthorizationServerState, credentialRequest: Request, holderJWK: JWK): Promise<{ credential?: any, error?: Error }>;

	exportCredentialSupportedObject(): any;
}


export interface VCDMSupportedCredentialProtocol extends SupportedCredentialProtocol {
	metadata(): any | any[] ;
	schema?(): any | any[] ;
}
