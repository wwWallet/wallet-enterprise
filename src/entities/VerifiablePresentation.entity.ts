import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";
import { VerifiableCredentialFormat } from "../types/oid4vci";

export enum VerificationStatus {
	REVOKED,
	EXPIRED,
	NOT_VALID_YET,
	VALID
}

export type ClaimRecord = {
	name: string;
	value: string;
};

export type PresentationClaims = {
	[descriptor_id: string]: Array<ClaimRecord>;
}

@Entity({ name: "verifiable_presentation" })
export class VerifiablePresentationEntity {
	@PrimaryGeneratedColumn()
	id: number = 0;

	@Column({ name: "presentation_definition_id", type: "varchar", nullable: true })
	presentation_definition_id?: string; // same with scope


	@Column({ name: "raw_presentation", type: "longtext", nullable: true })
	// @ts-ignore
	private _raw_presentation?: Buffer;
	set raw_presentation(value: string | null) {
		if (value) {
			this._raw_presentation = Buffer.from(value);
			return;
		}
		this._raw_presentation = undefined;
	}

	get raw_presentation(): string | null {
		if (this._raw_presentation) {
			return this._raw_presentation?.toString();
		}
		return null;
	}

	@Column({ name: "presentation_submission", type: "blob", nullable: true })
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


	@Column({ name: "claims", type: "blob", nullable: true })
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

	@Column({ name: "date", type: "date", nullable: true })
	date?: Date;

	@Column({ name: "format", type: "enum", enum: VerifiableCredentialFormat, nullable: true })
	format?: VerifiableCredentialFormat;
	
	@Column({ name: "status", type: "boolean", nullable: true })
	status?: boolean;


	@Column({ name: "state", type: "varchar", nullable: true })
	state?: string;
}