import { SignVerifiableCredentialJWT } from "@gunet/ssi-sdk";
import { randomUUID } from "crypto";
import { importJWK, JWK } from "jose";
import { CategorizedRawCredential, CategorizedRawCredentialViewRow, CategorizedRawCredentialView } from "../../openid4vci/Metadata";
import { VerifiableCredentialFormat, Display, CredentialSupportedJwtVcJson } from "../../types/oid4vci";
import { UserSession } from "../../RedisModule";
import { SupportedCredentialProtocol } from "../../lib/CredentialIssuerConfig/SupportedCredentialProtocol";
import { CredentialIssuerConfig } from "../../lib/CredentialIssuerConfig/CredentialIssuerConfig";
import { DiplomaEntry, getDiplomasBySSN } from "../../lib/resourceServer";
import { EuropassCredentialSubjectBuilder } from "../../lib/CredentialSubjectBuilders/EuropassCredentialSubjectBuilder/EuropassCredentialSubjectBuilder";
import { CredentialSubject } from "../../lib/CredentialSubjectBuilders/CredentialSubject.type";
import { LearningEntitlementBuilder } from "../../lib/CredentialSubjectBuilders/EuropassCredentialSubjectBuilder/LearningEntitlement/LearningEntitlementBuilder";
import config from "../../../config";

/**
 * This class can be used for parameterizing the types  and the issuer of a Supported Credential
 */
export class EdiplomasBlueprint implements SupportedCredentialProtocol {

	/**
	 * Constructor of SupportedCredential must include any
	 * parameters that differentiate the credentials between them.
	 * In our case, the blueprintID for eDiplomas specifies the type of the credential
	 * because the blueprintID is added into the credential type
	 * @param issuerConfiguration 
	 * @param blueprintId 
	 */
	constructor(private issuerConfiguration: CredentialIssuerConfig, private blueprintId: string) { }
	



	getCredentialIssuerConfig(): CredentialIssuerConfig {
		return this.issuerConfiguration;
	}
	getId(): string {
		return `urn:ediplomas:blueprint:${this.blueprintId}`;
	}
	getFormat(): VerifiableCredentialFormat {
		return VerifiableCredentialFormat.JWT_VC_JSON
	}
	getTypes(): string[] {
		return ["VerifiableCredential", "VerifiableAttestation", "Bachelor", this.getId()];
	}
	getDisplay(): Display {
		return {
			name: "Europass Diploma",
			logo: { url: config.url + "/images/EuropassUoaCard.png" },
			background_color: "#8fbfec"
		}
	}



	async getResources(userSession: UserSession): Promise<CategorizedRawCredential<any>[]> {
		console.log("user session2 = ", userSession)
		const diplomas = await getDiplomasBySSN(userSession.additionalData?.ssn as string);
		const categorizedRawDiplomas: CategorizedRawCredential<DiplomaEntry>[] = diplomas
			.filter(rawDiploma => rawDiploma.blueprintID == this.blueprintId)
			.map((rawDiploma) => {
				const rows: CategorizedRawCredentialViewRow[] = [
					{ name: "Family Name", value: rawDiploma.familyName },
					{ name: "First Name", value: rawDiploma.firstName },
					{ name: "Grade", value: rawDiploma.grade },
					{ name: "Institution Name", value: rawDiploma.institutionName },
				];
				const view: CategorizedRawCredentialView = { rows };
				
				return {
					credential_id: "diploma:"+randomUUID(),
					credentialIssuerIdentifier: this.issuerConfiguration.credentialIssuerIdentifier,
					supportedCredentialIdentifier: this.getId(),
					rawData: rawDiploma,
					view: view
				}
			})
		return categorizedRawDiplomas;
	}
	
	async signCredential(userSession: UserSession, holderDID: string): Promise<{ format: VerifiableCredentialFormat; credential: any; }> {
		console.log("(format, types, sessionId) = ")
		console.log("User session = ", userSession);

		if (!userSession?.categorizedRawCredentials) {
			throw "Categorized raw credentials not found";
		}

		console.log("ID = ", this.getId())
		const selectedCategorizedCredential: CategorizedRawCredential<DiplomaEntry> = userSession.categorizedRawCredentials
			.filter(crc => crc.supportedCredentialIdentifier == this.getId())
			[0];

		// shouldn't I pop the credential from the userSession.categorizedRawCredentials ?
		
		const diploma: CredentialSubject = new EuropassCredentialSubjectBuilder()
			.setId(holderDID)
			.addEntitlement(new LearningEntitlementBuilder()
				.setId(selectedCategorizedCredential.credential_id)
				.setIssuedDate(new Date())
				.setTitle(selectedCategorizedCredential.rawData.title)
				.build())
			.addEntitlement(new LearningEntitlementBuilder()
				.setId(selectedCategorizedCredential.credential_id)
				.setIssuedDate(new Date())
				.setTitle(selectedCategorizedCredential.rawData.title)
				.build())
			.build();
		
		const jwt = await new SignVerifiableCredentialJWT()
			.setProtectedHeader({ alg: "ES256", kid: this.getCredentialIssuerConfig().legalPersonWallet.keys.ES256?.id })
			.setJti(selectedCategorizedCredential.credential_id)
			.setSubject(holderDID)
			.setIssuedAt()
			.setExpirationTime('1y')
			.setContext([])
			.setType(this.getTypes())
			.setIssuer(this.getCredentialIssuerConfig().legalPersonWallet.did)
			.setCredentialSubject(diploma)
			.setCredentialSchema("https://api-pilot.ebsi.eu/trusted-schemas-registry/v2/schemas/0x4dd3926cd92bb3cb64fa6c837539ed31fc30dd38a11266a91678efa7268cde09")
			.sign(await importJWK(this.getCredentialIssuerConfig().legalPersonWallet.keys.ES256?.privateKeyJwk as JWK, "ES256"));

		console.log("Verifiable credential = ", jwt)
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