import { config } from "../../../config";
import { CategorizedRawCredentialView, CategorizedRawCredentialViewRow } from "../../openid4vci/Metadata";
import { VerifiableCredentialFormat } from "wallet-common/dist/types";
import { VCDMSupportedCredentialProtocol } from "../../lib/CredentialIssuerConfig/SupportedCredentialProtocol";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { CredentialView } from "../../authorization/types";
import { randomUUID } from "node:crypto";
import { CredentialSigner } from "../../services/interfaces";
import { JWK } from "jose";
import base64url from "base64url";
import { Request } from "express";
import { issuerSigner } from "../../configuration/issuerSigner";
import { parsePorData } from "../datasetParser";
import path from "node:path";
import fs from 'fs';
import { AuthenticationChain, AuthenticationChainBuilder } from "../../authentication/AuthenticationComponent";
import { CONSENT_ENTRYPOINT } from "../../authorization/constants";
import { GenericAuthenticationMethodSelectionComponent } from "../../authentication/authenticationComponentTemplates/GenericAuthenticationMethodSelectionComponent";
import { GenericVIDAuthenticationComponent } from "../../authentication/authenticationComponentTemplates/GenericVIDAuthenticationComponent";
import { UserAuthenticationMethod } from "../../types/UserAuthenticationMethod.enum";
import { initializeCredentialEngine } from "../../lib/initializeCredentialEngine";
import { createSRI } from "../../lib/sriGenerator";
import { porMetadata } from "./typeMetadata/porMetadata";
import { porSchema } from "./schema/porSchema";
import { convertSdjwtvcToOpenid4vciClaims } from "../../lib/convertSdjwtvcToOpenid4vciClaims";

const datasetName = "por-dataset.xlsx";
parsePorData(path.join(__dirname, `../../../../dataset/${datasetName}`)) // test parse

export class PorSupportedCredentialSdJwtDeferred implements VCDMSupportedCredentialProtocol {

	porEntryMap = new Map<string, unknown[]>();

	constructor() { }

	getAuthenticationChain(): AuthenticationChain {
		return new AuthenticationChainBuilder()
			.addAuthenticationComponent(new GenericAuthenticationMethodSelectionComponent(this.getScope() + "-auth-method", CONSENT_ENTRYPOINT, [{ code: UserAuthenticationMethod.VID_AUTH, description: "Authentication with PID" }]))
			.addAuthenticationComponent(new GenericVIDAuthenticationComponent(this.getScope() + "-vid-authentication", CONSENT_ENTRYPOINT, {
				"family_name": { input_descriptor_constraint_field_name: "Last Name" },
				"given_name": { input_descriptor_constraint_field_name: "First Name" },
				"birth_date": { input_descriptor_constraint_field_name: "Date of Birth", parser: (value: string) => new Date(value).toISOString() },
			}, "PidMinimal", "PID", this.getDisplay().name))
			.build();
	}

	getScope(): string {
		return "por:sd_jwt_vc";
	}

	getCredentialSigner(): CredentialSigner {
		return issuerSigner;
	}

	getId(): string {
		return "urn:eu.europa.ec.eudi:por:1:deferred";
	}
	getFormat(): VerifiableCredentialFormat {
		return VerifiableCredentialFormat.DC_SDJWT;
	}
	getTypes(): string[] {
		return ["VerifiableCredential", "VerifiableAttestation", "POR", this.getId()];
	}

	getDisplay() {
		return {
			name: `Power of Representation (${this.getFormat()}) - Deferred`,
			description: "Power of Representation - SD-JWT VC",
			background_image: { uri: config.url + "/images/background-image.png" },
			background_color: "#c3b25d",
			text_color: "#363531",
			locale: 'en-US',
		}
	}

	async getProfile(userSession: AuthorizationServerState): Promise<CredentialView | null> {
		if (!userSession?.family_name || !userSession?.given_name || !userSession?.birth_date) {
			return null;
		}
		const users = parsePorData(path.join(__dirname, "../../../../dataset/por-dataset.xlsx"));

		if (!users) {
			console.error("Failed to load users")
			return null;
		}

		const svgText = fs.readFileSync(path.join(__dirname, "../../../../public/images/template-por.svg"), 'utf-8');

		let porEntry = users.filter((por) =>
			por.family_name == userSession.family_name &&
			por.given_name == userSession.given_name &&
			new Date(por.birth_date).toISOString() == new Date(userSession.birth_date as string).toISOString()
		)[0];

		console.log("Por entry = ", porEntry)
		porEntry = {
			...porEntry,
			"effective_from_date": undefined,
			"effective_until_date": undefined,
		};

		const credentialView: CredentialView = await (async () => {
			const rows: CategorizedRawCredentialViewRow[] = [
				{ name: "Legal entity name", value: porEntry.legal_name },
				{ name: "Legal entity ID", value: porEntry.legal_person_identifier },
				{ name: "Full Represent. Powers", value: porEntry.full_powers }
			];
			const rowsObject: CategorizedRawCredentialView = { rows };


			const { credentialRendering } = await initializeCredentialEngine();
			const dataUri = await credentialRendering.renderSvgTemplate({
				json: { ...porEntry },
				credentialImageSvgTemplate: svgText,
				sdJwtVcMetadataClaims: this.metadata().claims,
			});

			if (!dataUri) {
				throw new Error("Could not render svg");
			}

			return {
				credential_id: this.getId(),
				credential_supported_object: this.exportCredentialSupportedObject(),
				view: rowsObject,
				credential_image: dataUri,
			}
		})();


		return credentialView;
	}

	async getPorData(userSession: AuthorizationServerState, request: Request) {
		const { session_id } = userSession;
		const { transaction_id } = request.body;
		if (!session_id) {
			console.error("session_id missing during getPorData");
			return [null, new Error("invalid_transaction_id")];
		}
		if (transaction_id && transaction_id !== session_id) {
			console.error("transaction_id and session_id are different");
			return [null, new Error("invalid_transaction_id")];
		}
		const creds = this.porEntryMap.get(session_id);
		if (!creds) { // if no por entries exist in the map, then store empty array
			this.porEntryMap.set(session_id, []);
		}
		else if (creds.length > 0) {
			const first = creds.pop();
			this.porEntryMap.set(session_id, [...creds]);
			return [first, null];
		}
		else if (transaction_id && creds.length === 0) {
			console.log("Creds length = 0");
			return [null, new Error("issuance_pending")];
		}

		const users = parsePorData(path.join(__dirname, "../../../../dataset/por-dataset.xlsx"));
		if (!users) {
			console.log("Cannot read dataset");
			return [null, new Error("invalid_transaction_id")];
		}
		const porEntry = users.filter((por) =>
			por.family_name == userSession.family_name &&
			por.given_name == userSession.given_name &&
			new Date(por.birth_date).toISOString() == new Date(userSession.birth_date as string).toISOString()
		)[0];
		setTimeout(() => { // fill the data after 5 seconds
			const credentials = creds ?? [];
			this.porEntryMap.set(`${session_id}`, [...credentials as any, porEntry]);
		}, 5000);
		return [null, new Error("not ready")];
	}

	async generateCredentialResponse(userSession: AuthorizationServerState, request: Request, holderPublicKeyJwk: JWK): Promise<{ credential?: unknown; error?: Error }> {
		if (!userSession?.family_name || !userSession.given_name || !userSession.birth_date) {
			console.log("Cannot generate credential: family_name or given_name or birth_date is missing")
			throw new Error("Cannot generate credential: family_name or given_name or birth_date is missing");
		}
		if (request.body.transaction_id && (!userSession.scope || !userSession.scope.split(' ').includes(this.getScope()))) {
			console.log("Not the correct credential");
			throw new Error("Not the correct credential");
		}
		if (!request.body.transaction_id && (request.body?.credential_configuration_id != this.getId() || !userSession.scope || !userSession.scope.split(' ').includes(this.getScope()))) {
			console.log("Not the correct credential");
			throw new Error("Not the correct credential");
		}

		const [porEntry, error] = await this.getPorData(userSession, request) as any;
		if (error) {
			console.info("Por entry not ready");
			return { error: error };
		}

		const payload = {
			"cnf": {
				"jwk": holderPublicKeyJwk
			},
			"vct": this.metadata().vct,
			"vct#integrity": createSRI(this.metadata()),
			"jti": `urn:por:${randomUUID()}`,
			"legal_person_identifier": String(porEntry.legal_person_identifier),
			"legal_name": String(porEntry.legal_name),
			"full_powers": String(porEntry.full_powers),

			"effective_from_date": new Date(porEntry.effective_from).toISOString(),
			"effective_until_date": porEntry.effective_until && new Date(porEntry.effective_until).toISOString(),
			"eService": porEntry.eService == "" ? null : porEntry.eService,
			"issuing_authority": porEntry.issuing_authority,
			"issuing_country": porEntry.issuing_country
		};


		const disclosureFrame = {
			legal_person_identifier: true,
			legal_name: true,
			full_powers: true,
			effective_until_date: true,
			effective_from_date: true,
			eService: true,
			issuing_authority: true,
			issuing_country: true
		};

		const { credential } = await this.getCredentialSigner()
			.signSdJwtVc(payload, { typ: VerifiableCredentialFormat.DC_SDJWT, vctm: [base64url.encode(JSON.stringify(this.metadata()))] }, disclosureFrame);
		const response = {
			credential: credential
		};

		return response;
	}

	public metadata(): any {
		return porMetadata;
	}

	public schema(): any {
		return porSchema;
	}

	exportCredentialSupportedObject(): any {
		return {
			scope: this.getScope(),
			vct: this.metadata().vct,
			display: [this.getDisplay()],
			format: this.getFormat(),
			cryptographic_binding_methods_supported: ["jwk"],
			credential_signing_alg_values_supported: ["ES256"],
			proof_types_supported: {
				jwt: {
					proof_signing_alg_values_supported: ["ES256"]
				}
			},
			claims: convertSdjwtvcToOpenid4vciClaims(this.metadata().claims, this.schema())
		}
	}
}
