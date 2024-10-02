import { JWK } from "jose";
import { CredentialView } from "../../authorization/types";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { VerifiableCredentialFormat, Display } from "../../types/oid4vci";
import { CredentialSigner } from "../../services/interfaces";
import { Request } from "express";


export interface SupportedCredentialProtocol {

	getScope(): string;
	getCredentialSigner(): CredentialSigner;
	getId(): string;
	getFormat(): VerifiableCredentialFormat;
	getTypes(): string[];
	getDisplay(): Display;

	getProfile(userSession: AuthorizationServerState): Promise<CredentialView | null>;
	generateCredentialResponse(userSession: AuthorizationServerState, credentialRequest: Request, holderJWK: JWK): Promise<{ format?: VerifiableCredentialFormat, credential?: any, acceptance_token?: string }>;


	
	exportCredentialSupportedObject(): any;
}
