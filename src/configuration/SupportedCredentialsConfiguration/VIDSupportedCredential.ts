import config from "../../../config";
import { UserSession } from "../../RedisModule";
import { CategorizedRawCredential, CategorizedRawCredentialView, CategorizedRawCredentialViewRow } from "../../openid4vci/Metadata";
import { VerifiableCredentialFormat, Display, CredentialSupportedJwtVcJson } from "../../types/oid4vci";
import { CredentialSubject } from "../../lib/CredentialSubjectBuilders/CredentialSubject.type";
import { VIDEntry, getVIDByTaxisId } from "../../lib/resourceServer";
import { CredentialIssuerConfig } from "../../lib/CredentialIssuerConfig/CredentialIssuerConfig";
import { SupportedCredentialProtocol } from "../../lib/CredentialIssuerConfig/SupportedCredentialProtocol";
import { SignVerifiableCredentialJWT } from "@gunet/ssi-sdk";
import { JWK, importJWK } from 'jose';
import { randomUUID } from 'node:crypto';

export class VIDSupportedCredential implements SupportedCredentialProtocol {

  constructor(private credentialIssuerConfig: CredentialIssuerConfig) { }
  getCredentialIssuerConfig(): CredentialIssuerConfig {
    return this.credentialIssuerConfig;
  }
  getId(): string {
    return "urn:credential:vid"
  }
  getFormat(): VerifiableCredentialFormat {
    return VerifiableCredentialFormat.JWT_VC_JSON;
  }
  getTypes(): string[] {
    return ["VerifiableCredential", "VerifiableAttestation", "VerifiableId", this.getId()];
  }
  getDisplay(): Display {
		return {
			name: "Verifiable ID",
			logo: { url: config.url + "/images/vidCard.png" },
			background_color: "#4CC3DD"
		}
  }


  async getResources(userSession: UserSession): Promise<CategorizedRawCredential<any>[]> {
		console.log("user session = ", userSession)
    if (!userSession.additionalData?.taxisid) {
      return [];
    }
		const vids = [await getVIDByTaxisId(userSession.additionalData.taxisid)];
		const categorizedRawVIDs: CategorizedRawCredential<VIDEntry>[] = vids
			.map((vid) => {
				const rows: CategorizedRawCredentialViewRow[] = [
					{ name: "Family Name", value: vid.familyName },
					{ name: "First Name", value: vid.firstName },
					{ name: "Personal Identifier", value: vid.personalIdentifier },
					{ name: "Date of Birth", value: vid.birthdate },
				];
				const view: CategorizedRawCredentialView = { rows };
				
				return {
					credential_id: "vid:"+randomUUID(),
					credentialIssuerIdentifier: this.getCredentialIssuerConfig().credentialIssuerIdentifier,
					supportedCredentialIdentifier: this.getId(),
					rawData: vid,
					view: view
				}
			})
		return categorizedRawVIDs;
  }
  
  async signCredential(userSession: UserSession, holderDID: string): Promise<{ format: VerifiableCredentialFormat; credential: any; }> {
		console.log("User session = ", userSession);
    if (!userSession?.categorizedRawCredentials) {
			throw "Categorized raw credentials not found";
		}

    const selectedCategorizedCredential: CategorizedRawCredential<VIDEntry> = userSession.categorizedRawCredentials
    .filter(crc => crc.supportedCredentialIdentifier == this.getId())
    [0];

		const vid: CredentialSubject = {
			familyName: selectedCategorizedCredential.rawData.familyName,
			firstName: selectedCategorizedCredential.rawData.firstName,
			id: holderDID,
			personalIdentifier: selectedCategorizedCredential.rawData.personalIdentifier,
			dateOfBirth: selectedCategorizedCredential.rawData.birthdate
		} as any;

    const jwt = await new SignVerifiableCredentialJWT()
      .setProtectedHeader({ alg: "ES256", kid: this.getCredentialIssuerConfig().legalPersonWallet.keys.ES256?.id })
      .setJti(selectedCategorizedCredential.credential_id)
			.setSubject(holderDID)
      .setIssuedAt()
      .setExpirationTime('1y')
      .setContext([])
      .setType(this.getTypes())
      .setIssuer(this.getCredentialIssuerConfig().legalPersonWallet.did)
      .setCredentialSubject(vid)
      .setCredentialSchema("https://api-pilot.ebsi.eu/trusted-schemas-registry/v2/schemas/z8Y6JJnebU2UuQQNc2R8GYqkEiAMj3Hd861rQhsoNWxsM")
      .sign(await importJWK(this.getCredentialIssuerConfig().legalPersonWallet.keys.ES256?.privateKeyJwk as JWK, "ES256"));
    
      const response = {
      format: this.getFormat(),
      credential: jwt
    };

    return response;
  }

	exportCredentialSupportedObject(): CredentialSupportedJwtVcJson {
		return {
			id: this.getId(),
			format: this.getFormat(),
			display: [ this.getDisplay() ],
			types: this.getTypes(),
			cryptographic_binding_methods_supported: ["ES256"]
		}
	}

}

