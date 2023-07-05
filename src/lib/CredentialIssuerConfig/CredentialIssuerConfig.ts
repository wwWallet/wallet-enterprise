
import { CredentialIssuerMetadata } from "../../types/oid4vci";
import { LegalPersonWallet } from "../LegalPersonWallet.type";
import { SupportedCredentialProtocol } from "./SupportedCredentialProtocol";
import { Request, Response } from 'express';
import * as _ from 'lodash';

export class CredentialIssuerConfig {

	constructor(
		public credentialIssuerIdentifier: string,
		public legalPersonWallet: LegalPersonWallet,
		public authorizationServerURL: string,
		public credentialEndpointURL: string,
		public supportedCredentials: SupportedCredentialProtocol[] = []
	) { }

	/**
	 * @throws
	 * @param supportedCredential 
	 * @returns 
	 */
	addSupportedCredential(supportedCredential: SupportedCredentialProtocol): this {
		const query = this.supportedCredentials.filter(sc => 
			sc.getFormat() == supportedCredential.getFormat() &&
			_.isEqual(sc.getTypes(), supportedCredential.getTypes())
		);

		if (query.length > 0)
			throw `Supported credential with id ${supportedCredential.getId()} cannot be added because there is supported credential with same (type, format) that already exists`;
		
		const queryForId = this.supportedCredentials.filter(sc =>
			sc.getId() == supportedCredential.getId()
		);
		if (queryForId.length > 0)
			throw `Supported credential with id ${supportedCredential.getId()} already exists`;

		this.supportedCredentials.push(supportedCredential);
		return this;
	}

	exportIssuerMetadata(): CredentialIssuerMetadata {
		return {
			credential_issuer: this.credentialIssuerIdentifier,
			authorization_server: this.authorizationServerURL,
			credential_endpoint: this.credentialEndpointURL,
			credentials_supported: this.supportedCredentials.map(sc => sc.exportCredentialSupportedObject())
		}
	}

	exposeConfiguration(app: any) {
		let urlPath = new URL(this.credentialIssuerIdentifier).pathname;
		if (urlPath == "/") urlPath = "";
		app.get(`${urlPath}/.well-known/openid-credential-issuer`, async (_req: Request, res: Response) => {
			const metadata = this.exportIssuerMetadata()
			return res.send(metadata);
		})
	}
}







