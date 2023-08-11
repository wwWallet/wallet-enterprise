import axios from "axios";
import { AuthorizationDetailsSchemaType, CredentialResponseSchemaType, VerifiableCredentialFormat } from "../../types/oid4vci";


export class CredentialIssuersMap {

	private credentialIssuersIdentifiers: string[] = [];

	constructor() { }

	addCredentialIssuer(credentialIssuerId: string): this {
		this.credentialIssuersIdentifiers.push(credentialIssuerId);
		return this;
	}

	async getNonSignedCredentials(authorizationDetails: AuthorizationDetailsSchemaType): Promise<any> {
		const credentials = [];
		for (const ad of authorizationDetails) {
			if (ad.locations) {
				const nonSignedCredentialsFromAllLocations = (await Promise.all(ad.locations.map(async (location) => {
					if (!this.credentialIssuersIdentifiers.includes(location)) { // invalid location
						return null;
					}
					try {
						const res = await axios.post(
							location + "/credential/raw",
							{ types: ad.types },
							{ headers: { authorization: "Basic 13&dffd" }});
							return res.data;
					}
					catch(err) { return null; }
				}))).filter(c => c != null);
				credentials.push(...nonSignedCredentialsFromAllLocations);
			}
		}
		return credentials;
	}

	async getSignedCredential(_types: string[], _format: VerifiableCredentialFormat, _proof: any): Promise<CredentialResponseSchemaType> {
		throw new Error("not implemented")
	}
}