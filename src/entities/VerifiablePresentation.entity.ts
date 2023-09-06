import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

export enum VerificationStatus {
	REVOKED,
	EXPIRED,
	NOT_VALID_YET,
	VALID
}

@Entity({ name: "verifiable_presentation" })
export class VerifiablePresentationEntity {
	@PrimaryGeneratedColumn()
	id: number = 0;

	@Column({ name: "presentation_definition_id", type: "varchar", nullable: true })
	presentation_definition_id?: string; // same with scope

	@Column({ name: "raw_presentation", type: "blob", nullable: true })
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

	@Column({ name: "format", type: "varchar", nullable: true })
	format?: string;

	@Column({ name: "status", type: "boolean", nullable: true })
	status?: boolean;

}