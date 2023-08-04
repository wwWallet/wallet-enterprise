import config from "../../../config";
import { UserSession } from "../../RedisModule";
import { CategorizedRawCredential, CategorizedRawCredentialViewRow, IssuanceFlow } from "../../openid4vci/Metadata";
import { VerifiableCredentialFormat, Display, CredentialSupportedJwtVcJson } from "../../types/oid4vci";
import { CredentialIssuerConfig } from "../../lib/CredentialIssuerConfig/CredentialIssuerConfig";
import { SupportedCredentialProtocol } from "../../lib/CredentialIssuerConfig/SupportedCredentialProtocol";
import { SignVerifiableCredentialJWT } from "@gunet/ssi-sdk";
import { randomUUID } from 'node:crypto';
import { appContainer } from "../../services/inversify.config";
import { FilesystemKeystoreService } from "../../services/FilesystemKeystoreService";

const keystoreService = appContainer.resolve(FilesystemKeystoreService);

export class CTWalletSameDeferredSupportedCredential implements SupportedCredentialProtocol {

  constructor(private credentialIssuerConfig: CredentialIssuerConfig) { }
	issuanceFlow(): IssuanceFlow {
		return IssuanceFlow.DEFERRED
	}
  getCredentialIssuerConfig(): CredentialIssuerConfig {
    return this.credentialIssuerConfig;
  }
  getId(): string {
    return "urn:credential:ct-wallet-deferred"
  }
  getFormat(): VerifiableCredentialFormat {
    return VerifiableCredentialFormat.JWT_VC_JSON;
  }
  getTypes(): string[] {
    return ["VerifiableCredential","VerifiableAttestation","CTWalletSameDeferred"];
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

		const rows: CategorizedRawCredentialViewRow[] = [
			{ name: "Family Name", value: "" },
			{ name: "First Name", value: "" },
			{ name: "Personal Identifier", value: "" },
			{ name: "Date of Birth", value: "" },
		];
		const categorizedCredential: CategorizedRawCredential<any> = {
			view: { rows },
			credential_id: "ct:" + randomUUID(),
			credentialIssuerIdentifier: this.getCredentialIssuerConfig().credentialIssuerIdentifier,
			supportedCredentialIdentifier: this.getId(),
			issuanceFlow: this.issuanceFlow(),
			readyToBeSigned: false,
		}
		return [ categorizedCredential ];
  }
  
  async generateCredentialResponse(userSession: UserSession, holderDID: string): Promise<{ format?: VerifiableCredentialFormat; credential?: any; acceptance_token?: string }> {
		console.log("User session = ", userSession);
    const nonSignedJwt = new SignVerifiableCredentialJWT()
      .setJti(`${this.getId()}:${randomUUID()}`)
			.setSubject(holderDID)
      .setIssuedAt()
      .setExpirationTime('1y')
      .setContext(["https://www.w3.org/2018/credentials/v1"])
      .setType(this.getTypes())
      .setCredentialSubject({ id: holderDID })
      .setCredentialSchema("https://api-pilot.ebsi.eu/trusted-schemas-registry/v2/schemas/z8Y6JJnebU2UuQQNc2R8GYqkEiAMj3Hd861rQhsoNWxsM");

		const { credential } = await keystoreService.signVcJwt(this.getCredentialIssuerConfig().walletId, nonSignedJwt);
    const response = {
      format: this.getFormat(),
      credential: credential
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

