import { CredentialIssuer } from "./CredentialIssuerConfig/CredentialIssuer";


export class CredentialIssuersRepository {

	private issuersMap = new Map<string,CredentialIssuer>();

	constructor(issuersArray: CredentialIssuer[]) {
		issuersArray.map((i) => this.issuersMap.set(i.credentialIssuerIdentifier, i));
	}

	public getCredentialIssuer(credentialIssuerId: string) {
		return this.issuersMap.get(credentialIssuerId);
	}

	public getAllCredentialIssuers() {
		return Array.from(this.issuersMap.values());
	}
}