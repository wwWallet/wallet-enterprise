import { JWK } from "jose";
import { CredentialView } from "../../authorization/types";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { VerifiableCredentialFormat } from "../../types/oid4vci";
import { CredentialSigner } from "../../services/interfaces";
import { Request } from "express";


export interface SupportedCredentialProtocol {

	getScope(): string;
	getCredentialSigner(): CredentialSigner;
	getId(): string;
	getFormat(): VerifiableCredentialFormat;
	getTypes(): string[];
	getDisplay(): any;

	getProfile(userSession: AuthorizationServerState): Promise<CredentialView | null>;
	generateCredentialResponse(userSession: AuthorizationServerState, credentialRequest: Request, holderJWK: JWK): Promise<{ format?: VerifiableCredentialFormat, credential?: any, acceptance_token?: string }>;
	
	exportCredentialSupportedObject(): any;
}


export interface VCDMSupportedCredentialProtocol extends SupportedCredentialProtocol {
	/**
	 * VCDM draft spec https://github.com/danielfett/sd-jwt-vc-dm?tab=readme-ov-file#sd-jwt-vc-dm-credential-format
	 * @returns  an object according to https://vcstuff.github.io/sd-jwt-vc-types/draft-fett-oauth-sd-jwt-vc-types.html
	 */
	metadata(): any;
}
