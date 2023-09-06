import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";
import { AuthorizationDetailsSchemaType } from "../types/oid4vci";

@Entity({ name: "authorization_server_state" })
export class AuthorizationServerState {

	@PrimaryGeneratedColumn()
	id: number = 0;


	@Column({ name: "client_id", type: "varchar", nullable: true })
	client_id?: string;


	@Column({ name: "scope", type: "varchar", nullable: true })
	scope?: string;

	@Column({ name: "response_type", type: "varchar", nullable: true })
	response_type?: string;

	@Column({ name: "redirect_uri", type: "varchar", nullable: true })
	redirect_uri?: string;

	@Column({ name: "code_challenge", type: "varchar", nullable: true })
	code_challenge?: string;


	@Column({ name: "code_challenge_method", type: "varchar", nullable: true })
	code_challenge_method?: string;


	@Column({ name: "authorization_details", type: "blob", nullable: true })
	// @ts-ignore
	private _authorization_details?: Buffer;
	set authorization_details(value: AuthorizationDetailsSchemaType | null) {
		if (value) {
			this._authorization_details = Buffer.from(JSON.stringify(value));
			return;
		}
		this._authorization_details = undefined;
	}
	
	get authorization_details(): AuthorizationDetailsSchemaType | null {
		if (this._authorization_details) {
			return JSON.parse(this._authorization_details.toString()) as AuthorizationDetailsSchemaType;
		}
		return null;
	}


	@Column({ name: "authorization_code", type: "varchar", nullable: true })
	authorization_code?: string;


	@Column({ name: "pre_authorized_code", type: "varchar", nullable: true })
	pre_authorized_code?: string;


	@Column({ name: "state", type: "varchar", nullable: true })
	state?: string;

	@Column({ name: "grant_type", type: "varchar", nullable: true })
	grant_type?: string;


	@Column({ name: "user_pin", type: "varchar", nullable: true })
	user_pin?: string;


	// @Column({ name: "credential_identifiers", type: "varchar", nullable: true })
	// private _credential_identifiers?: string;
	// set credential_identifiers(value: string[] | null) {
	// 	if (value) {
	// 		this._credential_identifiers = value.join(" ");
	// 		return;
	// 	}
	// 	this._authorization_details = undefined; 
	// }
	
	// get credential_identifiers(): string[] | null {
	// 	if (this._credential_identifiers) {
	// 		return this._credential_identifiers.split(" ");
	// 	}
	// 	return null;
	// }
	


	
	// not needed to be added as columns in the database
	expires_in: number = -1;
	c_nonce: string = "";
	c_nonce_expires_in: number = -1;



	@Column({ name: "taxis_id", type: "varchar", nullable: true })
	taxis_id?: string;
	


	/**
	 * convert source into a format ready to be transmitted
	 * @param source
	 * @returns 
	 */
	static serialize(source: AuthorizationServerState): any {
		let dest = new AuthorizationServerState();
		dest = { ...source } as any;
		dest.authorization_details = source.authorization_details;
		dest._authorization_details = undefined; // not to be transmitted
		// dest.credential_identifiers = source.credential_identifiers;
		// dest._credential_identifiers = undefined; // not to be transmitted
		return dest;
	}

	/**
	 * 
	 * @param source 
	 * @returns 
	 */
	static deserialize(source: any): AuthorizationServerState {
		let dest = new AuthorizationServerState();
		dest = { ...source };
		dest.authorization_details = source.authorization_details;
		// dest.credential_identifiers = source.credential_identifiers; 
		return dest;
	}

}



// setTimeout(async () => {
// 	const userSessionRepository: Repository<AuthorizationServerState> = AppDataSource.getRepository(AuthorizationServerState);

// 	const newUserSession = new AuthorizationServerState();
// 	newUserSession.authorization_details = [{format: "jwt_vc", type: "openid_credential", types: ["x"]}];

// 	// Insert the new instance into the database
// 	userSessionRepository.save(newUserSession)
// 		.then((savedUserSession: any) => {
// 			console.log("User session saved:", savedUserSession);
// 			userSessionRepository.createQueryBuilder("session")
// 			.getOne()
// 			.then((res) => {
// 				if (res && res.authorization_details) {
// 					console.log("Authorization detail[0]= ", res.authorization_details[0]);

// 				}
// 			})
// 		})
// 		.catch((error: any) => {
// 			console.error("Error saving user session:", error);
// 		});
	
// }, 2000)
