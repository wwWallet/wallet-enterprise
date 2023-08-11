import { Request } from "express";
import { CredentialView } from "../authorization/types";
import { AuthorizationDetailsSchemaType, CredentialIssuerMetadata } from "../types/oid4vci";

export type AuthenticationResult = {
	authenticationComponentId: string;
	[x: string]: any;
}

export class CredentialIssuerResourceServer {

	exportCredentialIssuerMetadata(): CredentialIssuerMetadata {
		throw new Error("not implemented")
	}

	getNonSignedCredentials(_authenticationResults: AuthenticationResult[], _authorizationDetails: AuthorizationDetailsSchemaType): Promise<{ credentials: { types: string[], credential_view: CredentialView }[] }> {
		throw new Error("not implemented")
	}

	getSignedCredential(_req: Request, _res: Response) {
		// use access token to get the user's identity from the authorization server
		throw new Error("not implemented")
	}

}