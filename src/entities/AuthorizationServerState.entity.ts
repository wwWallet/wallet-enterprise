import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";
import { GrantType } from "../types/oid4vci";
import { UserAuthenticationMethod } from "../types/UserAuthenticationMethod.enum";


@Entity({ name: "authorization_server_state" })
export class AuthorizationServerState {

	@PrimaryGeneratedColumn()
	id: number = 0;

	@Column({ name: "session_id", type: "varchar", nullable: true })
	session_id?: string;

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


	@Column({ name: "credential_configuration_ids", type: "blob", nullable: true })
	// @ts-ignore
	private _credential_configuration_ids?: Buffer;
	set credential_configuration_ids(value: string[] | null) {
		if (value) {
			this._credential_configuration_ids = Buffer.from(JSON.stringify(value));
			return;
		}
		this._credential_configuration_ids = undefined;
	}
	
	get credential_configuration_ids(): string[] | null {
		if (this._credential_configuration_ids) {
			return JSON.parse(this._credential_configuration_ids.toString()) as string[];
		}
		return null;
	}


	@Column({ name: "authorization_code", type: "varchar", nullable: true })
	authorization_code?: string | null;


	@Column({ name: "pre_authorized_code", type: "varchar", nullable: true })
	pre_authorized_code?: string | null;

	@Column({ name: "issuer_state", type: "text", nullable: true })
	issuer_state?: string;

	@Column({ name: "state", type: "varchar", nullable: true })
	state?: string;

	@Column({ name: "grant_type", type: "enum", enum: GrantType, default: GrantType.PRE_AUTHORIZED_CODE, nullable: false })
	grant_type?: GrantType;


	@Column({ name: "user_pin", type: "varchar", nullable: true })
	user_pin?: string;

	@Column({ name: "user_pin_required", type: "boolean", nullable: true })
	user_pin_required?:  boolean;

	@Column({ name: "credential_issuer_identifier", type: "varchar", nullable: true })
	credential_issuer_identifier?: string;

	@Column({ name: "request_uri", type: "varchar", nullable: true})
	request_uri?: string;

	@Column({ name: "request_uri_expiration_timestamp", type: "int", nullable: true})
	request_uri_expiration_timestamp?: number;

	@Column({ name: "dpop_jwk", type: "varchar", nullable: true })
	dpop_jwk?: string;

	@Column({ name: "dpop_jti", type: "varchar", nullable: true })
	dpop_jti?: string;

	@Column({ name: "access_token", type: "varchar", nullable: true })
	access_token?: string;

	@Column({ name: "token_type", type: "varchar", nullable: true })
	token_type?: string;

	@Column({ name: "access_token_expiration_timestamp", type: "int", nullable: true })
	access_token_expiration_timestamp?: number;

	@Column({ name: "c_nonce", type: "varchar", nullable: true })
	c_nonce?: string;

	@Column({ name: "c_nonce_expiration_timestamp", type: "int", nullable: true})
	c_nonce_expiration_timestamp?: number;

	@Column({ name: "refresh_token", type: "varchar", nullable: true, default: () => "NULL" })
	refresh_token?: string;

	@Column({ name: "refresh_token_expiration_timestamp", type: "int", nullable: true, default: () => "NULL" })
	refresh_token_expiration_timestamp?: number;


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
	


	@Column({ name: "authentication_data", type: "blob", nullable: true, default: () => "NULL" })
	private _authenticationData?: string;
	get authenticationData(): any | null {
		if (this._authenticationData) {
			return JSON.parse(this._authenticationData.toString()) as any;
		}
		else {
			return null;
		}
	}
	set authenticationData(d: any) {
		this._authenticationData = JSON.stringify(d);
	}


	// not needed to be added as columns in the database

	@Column({ name: "ssn", type: "varchar", nullable: true })
	ssn?: string;

	@Column({ name: "pid_id", type: "varchar", nullable: true })
	pid_id?: string;

	@Column({ name: "family_name", type: "varchar", nullable: true })
	family_name?: string;

	@Column({ name: "given_name", type: "varchar", nullable: true })
	given_name?: string;

	@Column({ name: "birth_date", type: "varchar", nullable: true })
	birth_date?: string;


	@Column({ name: "document_number", type: "varchar", nullable: true })
	document_number?: string;


	/**
	 * this state random string will be used in order to expect a vid on a direct_post endpoint
	 */
	@Column({ name: "vid_auth_state", type: "varchar", nullable: true })
	vid_auth_state?: string;


	@Column({ name: "authentication_method", type: "enum", enum: UserAuthenticationMethod, nullable: true })
	authenticationMethod?: UserAuthenticationMethod;

	/**
	 * convert source into a format ready to be transmitted
	 * @param source
	 * @returns 
	 */
	static serialize(source: AuthorizationServerState): any {
		let dest = new AuthorizationServerState();
		dest = { ...source } as any;
		dest.credential_configuration_ids = source.credential_configuration_ids;
		dest._credential_configuration_ids = undefined; // not to be transmitted
		// dest.credential_identifiers = source.credential_identifiers;
		// dest._credential_identifiers = undefined; // not to be transmitted
		// dest.ediplomas_response = source.ediplomas_response;
		// dest._ediplomas_response = undefined;
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
		dest.credential_configuration_ids = source.credential_configuration_ids;
		// dest.ediplomas_response = source.ediplomas_response;
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
