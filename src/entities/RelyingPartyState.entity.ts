import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";
import { JWK } from "jose";

export type ClaimRecord = {
	key: string;
	name: string;
	value: string;
};

export type PresentationClaims = {
	[descriptor_id: string]: Array<ClaimRecord>;
}

@Entity({ name: "relying_party_state" })
export class RelyingPartyState {
	@PrimaryGeneratedColumn()
	id: number = 0;


	@Column({ name: "session_id", type: "varchar", nullable: false })
	session_id: string = "";

	@Column({ name: "is_cross_device", type: "boolean", nullable: false, default: true })
	is_cross_device: boolean = true;

	@Column({ name: "signed_request", type: "text", nullable: false })
	signed_request: string = "";

	@Column({ name: "state", type: "varchar", nullable: false })
	state: string = "";

	@Column({ name: "nonce", type: "varchar", nullable: false })
	nonce: string = "";

	@Column({ name: "callback_endpoint", type: "varchar", nullable: true , default: () => "NULL" })
	callback_endpoint: string | null = null;

	@Column({ name: "audience", type: "varchar", nullable: false })
	audience: string = "";

	@Column({ name: "presentation_definition_id", type: "varchar", nullable: false })
	presentation_definition_id: string = "";

	@Column({ name: "presentation_definition", type: "text", nullable: true })
	// @ts-ignore
	private _presentation_definition?: Buffer;
	set presentation_definition(value: any | null) {
		if (value) {
			this._presentation_definition = Buffer.from(JSON.stringify(value));
			return;
		}
		this._presentation_definition = undefined;
	}

	get presentation_definition(): any | null {
		if (this._presentation_definition) {
			return JSON.parse(this._presentation_definition?.toString());
		}
		return null;
	}

	@Column({ name: "dcql_query", type: "text", nullable: true })
	// @ts-ignore
	private _dcql_query?: Buffer;

	set dcql_query(value: any | null) {
		if (value) {
			this._dcql_query = Buffer.from(JSON.stringify(value));
			return;
		}
		this._dcql_query = undefined;
	}

	get dcql_query(): any | null {
		if (this._dcql_query) {
			return JSON.parse(this._dcql_query.toString());
		}
		return null;
	}

	@Column({ name: "rp_eph_kid", type: "varchar", nullable: false })
	rp_eph_kid: string = "";

	@Column({ name: "rp_eph_pub", type: "varchar", nullable: false })
	private _rp_eph_pub: string = "";
	set rp_eph_pub(value: JWK) {
		this._rp_eph_pub = JSON.stringify(value);
	}

	get rp_eph_pub(): JWK {
		return JSON.parse(this._rp_eph_pub?.toString()) as JWK;
	}

	@Column({ name: "rp_eph_priv", type: "varchar", nullable: false })
	private _rp_eph_priv: string = "";
	set rp_eph_priv(value: JWK) {
		this._rp_eph_priv = JSON.stringify(value);
	}

	get rp_eph_priv(): JWK {
		return JSON.parse(this._rp_eph_priv?.toString()) as JWK;
	}

	@Column({ name: "apv", type: "varchar", nullable: true, default: () => "NULL" })
	apv_jarm_encrypted_response_header: string | null = null;

	@Column({ name: "apu", type: "varchar", nullable: true, default: () => "NULL" })
	apu_jarm_encrypted_response_header: string | null = null;

	@Column({ name: "encrypted_response", type: "longtext", nullable: true, default: () => "NULL" })
	encrypted_response: string | null = null;

	@Column({ name: "vp_token", type: "longtext", nullable: true, default: () => "NULL" })
	vp_token: string | null = null;

	@Column({ name: "presentation_submission", type: "text", nullable: true })
	// @ts-ignore
	private _presentation_submission?: Buffer;
	set presentation_submission(value: any | null) {
		if (value) {
			this._presentation_submission = Buffer.from(JSON.stringify(value));
			return;
		}
		this._presentation_submission = undefined;
	}

	get presentation_submission(): any | null {
		if (this._presentation_submission) {
			return JSON.parse(this._presentation_submission?.toString());
		}
		return null;
	}

	@Column({ name: "response_code", type: "varchar", nullable: true, default: () => "NULL" })
	response_code: string | null = null;


	@Column({ name: "claims", type: "text", nullable: true })
	// @ts-ignore
	/**
	 * Includes the claims that were requested from the presentation definition
	 */
	private _claims?: Buffer;
	set claims(value: PresentationClaims | null) {
		if (value) {
			this._claims = Buffer.from(JSON.stringify(value));
			return;
		}
		this._claims = undefined;
	}

	get claims(): PresentationClaims | null {
		if (this._claims) {
			return JSON.parse(this._claims?.toString()) as PresentationClaims;
		}
		return null;
	}

	@Column({ name: "presentation_during_issuance_session", type: "varchar", nullable: true, default: () => "NULL" })
	presentation_during_issuance_session: string | null = null;

	@Column({ name: "date_created", type: "datetime", nullable: false })
	date_created: Date = new Date();
}
