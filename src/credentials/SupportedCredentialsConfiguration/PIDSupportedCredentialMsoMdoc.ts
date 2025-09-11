import { CategorizedRawCredentialView, CategorizedRawCredentialViewRow } from "../../openid4vci/Metadata";
import { VerifiableCredentialFormat } from "wallet-common/dist/types";
import { SupportedCredentialProtocol } from "../../lib/CredentialIssuerConfig/SupportedCredentialProtocol";
import { formatDateDDMMYYYY } from "../../lib/formatDate";
import { urlToBstr } from "../../lib/urlToBstr";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { CredentialView } from "../../authorization/types";
import { CredentialSigner } from "../../services/interfaces";
import { JWK } from "jose";
import { Request } from "express";
import { issuerSigner } from "../../configuration/issuerSigner";
import { parsePidData } from "../datasetParser";
import path from "node:path";
import { AuthenticationChain, AuthenticationChainBuilder } from "../../authentication/AuthenticationComponent";
import { CONSENT_ENTRYPOINT } from "../../authorization/constants";
import { GenericLocalAuthenticationComponent } from "../../authentication/authenticationComponentTemplates/GenericLocalAuthenticationComponent";
import { initializeCredentialEngine } from "../../lib/initializeCredentialEngine";
import { config } from "../../../config";

const datasetName = "vid-dataset.xlsx";
parsePidData(path.join(__dirname, `../../../../dataset/${datasetName}`)) // test parse

export class PIDSupportedCredentialMsoMdoc implements SupportedCredentialProtocol {


	constructor() { }

	getAuthenticationChain(): AuthenticationChain {
		return new AuthenticationChainBuilder()
			.addAuthenticationComponent(new GenericLocalAuthenticationComponent(this.getScope() + "-1-local", CONSENT_ENTRYPOINT, {
				"pid_id": { datasetColumnName: "pid_id", parser: (val: any) => String(val) },
			},
				async () => parsePidData(path.join(__dirname, "../../../../dataset/" + datasetName)) as any[],
				[{ username: "john", password: "secret" }, { username: "emily", password: "secret" }]
			))
			// .addAuthenticationComponent(new LocalAuthenticationComponent2("2-local", CONSENT_ENTRYPOINT))
			.build();
	}

	getScope(): string {
		return "pid:mso_mdoc";
	}

	getCredentialSigner(): CredentialSigner {
		return issuerSigner;
	}

	getId(): string {
		return "eu.europa.ec.eudi.pid.1";
	}

	getFormat(): VerifiableCredentialFormat {
		return VerifiableCredentialFormat.MSO_MDOC;
	}
	getTypes(): string[] {
		return ["VerifiableCredential", "VerifiableAttestation", "PID", this.getId()];
	}

	getDisplay() {
		return {
			name: `PID mDoc`,
			description: "Person Identification Data",
			background_image: { uri: config.url + "/images/background-image.png" },
			background_color: "#4CC3DD",
			text_color: "#000000",
			locale: 'en-US',
		}
	}

	async getProfile(userSession: AuthorizationServerState): Promise<CredentialView | null> {
		if (!userSession?.pid_id) {
			return null;
		}
		const users = parsePidData(path.join(__dirname, "../../../../dataset/vid-dataset.xlsx"));

		if (!users) {
			console.error("Failed to load users")
			return null;
		}

		const vids = users.filter(u => String(u.pid_id) == userSession?.pid_id);
		const credentialViews: CredentialView[] = await Promise.all(vids
			.map(async (vid) => {
				const rows: CategorizedRawCredentialViewRow[] = [
					{ name: "Family Name", value: vid.family_name },
					{ name: "Family Name at Birth", value: vid.family_name_birth },
					{ name: "Given Name", value: vid.given_name },
					{ name: "Given Name at Birth", value: vid.given_name_birth },
					{ name: "Birth Date", value: formatDateDDMMYYYY(vid.birth_date) },
					{ name: "Age Over 18", value: vid.age_over_18 },
					{ name: "Sex", value: vid.sex },
					{ name: "Nationality", value: vid.nationality },
					{ name: "Birth Place", value: vid.birth_place },
					{ name: "Resident Address", value: vid.resident_address },
					{ name: "Email Address", value: vid.email_address },
					{ name: "Mobile Phone", value: vid.mobile_phone_number },
					{ name: "Expiry Date", value: formatDateDDMMYYYY(vid.expiry_date) },
					{ name: "Document Number", value: vid.document_number },
				];
				const rowsObject: CategorizedRawCredentialView = { rows };


				const e = await initializeCredentialEngine();
				const dataUri = await e.openid4vcRendering.renderCustomSvgTemplate({
					signedClaims: { expiry_date: formatDateDDMMYYYY(vid.expiry_date) },
					displayConfig: {
						name: this.getDisplay().name,
						description: this.getDisplay().description,
						locale: this.getDisplay().locale,
						text_color: this.getDisplay().text_color,
					}
				}).then((res) => res).catch(() => null);

				if (!dataUri) {
					throw new Error("Could not render svg");
				}

				return {
					credential_id: this.getId(),
					credential_supported_object: this.exportCredentialSupportedObject(),
					view: rowsObject,
					credential_image: dataUri,
				}
			}));
		return credentialViews[0];
	}

	async generateCredentialResponse(userSession: AuthorizationServerState, request: Request, holderPublicKeyJwk: JWK): Promise<{ format: VerifiableCredentialFormat; credential: any; }> {
		if (!userSession?.pid_id) {
			console.log("Cannot generate credential: pid_id is missing")
			throw new Error("Cannot generate credential: pid_id is missing");
		}

		const users = parsePidData(path.join(__dirname, "../../../../dataset/vid-dataset.xlsx"));

		if (!users) {
			throw new Error("Failed to get users from dataset");
		}

		if (request.body?.credential_configuration_id != this.getId() || !userSession.scope || !userSession.scope.split(' ').includes(this.getScope())) {
			console.log("Not the correct credential");
			throw new Error("Not the correct credential");
		}

		const vidEntry = users?.filter(u => String(u.pid_id) == userSession.pid_id)[0];
		if (!vidEntry) {
			console.error("Possibly raw data was not found")
			throw new Error("Could not generate credential response");
		}

		const vid = {
			family_name: vidEntry.family_name,
			family_name_birth: vidEntry.family_name_birth,
			given_name: vidEntry.given_name,
			given_name_birth: vidEntry.given_name_birth,
			personal_administrative_number: vidEntry.personal_administrative_number,
			birth_date: new Date(vidEntry.birth_date).toISOString().split('T')[0],  // full-date format, according to ARF PID Rulebook
			issuing_authority: vidEntry.issuing_authority,
			issuing_country: vidEntry.issuing_country,
			issuing_jurisdiction: vidEntry.issuing_jurisdiction,
			document_number: String(vidEntry.document_number),
			issuance_date: new Date().toISOString().split('T')[0],  // full-date format, according to ARF PID Rulebook
			expiry_date: new Date(vidEntry.expiry_date).toISOString().split('T')[0],  // full-date format, according to ARF PID Rulebook
			age_over_18: String(vidEntry.age_over_18) == '1' ? true : false,
			age_over_21: String(vidEntry.age_over_21) == '1' ? true : false,
			age_in_years: vidEntry.age_in_years,
			age_birth_year: vidEntry.age_birth_year,
			sex: vidEntry.sex,
			nationality: vidEntry.nationality.split(','),
			birth_place: vidEntry.birth_place,
			resident_address: vidEntry.resident_address,
			resident_country: vidEntry.resident_country,
			resident_state: vidEntry.resident_region,
			resident_city: vidEntry.resident_city,
			resident_postal_code: vidEntry.resident_postal_code,
			resident_street: vidEntry.resident_street,
			resident_house_number: vidEntry.resident_house_number,
			portrait: vidEntry.sex == '1' ? await urlToBstr(config.url + "/images/male_portrait.jpg") : await urlToBstr(config.url + "/images/female_portrait.jpg"),
			email_address: vidEntry.email_address,
			mobile_phone_number: vidEntry.mobile_phone_number,
			trust_anchor: config.url + "/trust_anchor"
		};


		const { credential } = await this.getCredentialSigner()
			.signMsoMdoc(
				'eu.europa.ec.eudi.pid.1',
				new Map([
					['eu.europa.ec.eudi.pid.1', vid]
				]),
				holderPublicKeyJwk
			);

		const response = {
			format: this.getFormat(),
			credential: credential
		};

		return response;
	}

	exportCredentialSupportedObject(): any {
		return {
			scope: this.getScope(),
			doctype: this.getId(),
			display: [this.getDisplay()],
			format: this.getFormat(),
			cryptographic_binding_methods_supported: ["jwk"],
			credential_signing_alg_values_supported: ["ES256"],
			proof_types_supported: {
				jwt: {
					proof_signing_alg_values_supported: ["ES256"]
				}
			},
			"claims": [
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"family_name"
					],
					"mandatory": true,
					"display": [
						{
							"name": "Family Name",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"given_name"
					],
					"mandatory": true,
					"display": [
						{
							"name": "Given Name(s)",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"birth_date"
					],
					"mandatory": true,
					"display": [
						{
							"name": "Birth Date",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"birth_place"
					],
					"mandatory": true,
					"display": [
						{
							"name": "Birth Place",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"nationality"
					],
					"mandatory": true,
					"display": [
						{
							"name": "Nationality",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_address"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Resident Address",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_country"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Resident Country",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_state"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Resident State",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_city"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Resident City",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_postal_code"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Resident Postal Code",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_street"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Resident Street",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"resident_house_number"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Resident House Number",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"personal_administrative_number"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Personal Administrative Number",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"portrait"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Portrait Image",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"family_name_birth"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Birth Family Name(s)",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"given_name_birth"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Birth Given Name(s)",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"sex"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Sex",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"email_address"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Email Address",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"mobile_phone_number"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Mobile Phone Number",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"expiry_date"
					],
					"mandatory": true,
					"display": [
						{
							"name": "Expiry Date",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"issuing_authority"
					],
					"mandatory": true,
					"display": [
						{
							"name": "Issuance Authority",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"issuing_country"
					],
					"mandatory": true,
					"display": [
						{
							"name": "Issuing Country",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"document_number"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Document Number",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"issuing_jurisdiction"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Issuing Jurisdiction",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"issuance_date"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Issuance Date",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_over_18"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Age Over 18",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_in_years"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Age in Years",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"age_birth_year"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Age Year of Birth",
							"locale": "en-US"
						}
					]
				},
				{
					"path": [
						"eu.europa.ec.eudi.pid.1",
						"trust_anchor"
					],
					"mandatory": false,
					"display": [
						{
							"name": "Trust Anchor",
							"locale": "en-US"
						}
					]
				}
			]
		}
	}
}
