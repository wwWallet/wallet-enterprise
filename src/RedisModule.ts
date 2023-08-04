import { createClient } from 'redis';
import { Err, Ok, Result } from 'ts-results';
import config from '../config';
import logger, { newLogerr } from './logger';
import { CategorizedRawCredential } from './openid4vci/Metadata';
import { AuthorizationDetailsSchemaType, AuthorizationRequestQueryParamsSchemaType, GrantType } from './types/oid4vci';
import { AdditionalSessionData } from './configuration/Session/AdditionalSessionData.type';
import { CredentialView } from './authorization/types';

export enum DeviceType {
	SAME_DEVICE = "same_device",
	CROSS_DEVICE = "cross_device"
}


export enum SupportedCredentialIdentifier {
	EUROPASS = "Europass",
	STUDENT_ID = "StudentId"
}

export type UserSession = {
	id: string;

	lang?: string;

	authorizationReqParams?: AuthorizationRequestQueryParamsSchemaType;
	authorizationDetails?: AuthorizationDetailsSchemaType;
	grantType?: GrantType;


	authorization_code?: string;
	"pre-authorized_code"?: string;

	/**
	 *  Represents the issuance date of the Access Token 
	 * 	in ISO string format
	 */
	iat?: string;

	/**
	 * in seconds
	 */
	expires_in?: number;

	c_nonce?: string;

	/**
	 * in seconds
	 */
	c_nonce_expires_in?: number;
	access_token?: string;

	// not subject of change
	categorizedRawCredentials?: CategorizedRawCredential<any>[];
	credViewList?: CredentialView[];
	selectedCredentialIdList?: string[]; // the credential IDs selected from the categorizedRawCredentials


	additionalData?: AdditionalSessionData;
}

export class RedisModule {
	public redisClient;

	constructor() {
		// configure
		// https://github.com/redis/node-redis/blob/HEAD/docs/client-configuration.md
		this.redisClient = createClient({
			url: config.redis.url,
			password: config.redis.password
		});

		this.redisClient.on('error', (err: any) => console.log('Redis Client Error', err));

		this.redisClient.connect();
		this.redisClient.on('connect', () => console.log("Connected with redis"));
	}


	/**
	 * 
	 * @param sessid
	 * @param session 
	 * @returns 
	 */
	async storeUserSession(sessid: string, session: UserSession): Promise<Result<null, 'WRONG_SESSID_FORMAT' | 'FAILED_STORAGE_ON_REDIS'>> {

		try {
			// set expiration time for the session
			await this.redisClient.set('sessid:'+sessid, JSON.stringify(session), {
				EX: 10000000 // for 600 seconds = 10 minutes
			});
			return Ok(null);
		}
		catch(e) {
			logger.error(newLogerr(3001, "REDIS_ERR\n Details: " + e));
			return Err('FAILED_STORAGE_ON_REDIS');
		}
	}

	/**
	 * 
	 * @param nonce 
	 * @param sessid 
	 * @returns 
	 */
	async storeSessionNonce(nonce: string, sessid: string): Promise<Result<null, 'INVALID_SESSID' | 'FAILED_STORAGE_ON_REDIS'>> {
		const key = 'oid4vp:nonce:' + nonce;
		try {
			await this.redisClient.set(key, sessid, {
				EX: 10000 // for 600 seconds = 10 minutes
			});
			return Ok(null);
		}
		catch(e) {
			logger.error(newLogerr(3001, "REDIS_ERR\n Details: " + e));
			return Err('FAILED_STORAGE_ON_REDIS');
		}

	}

	/**
	 * @param sessid 
	 * @returns 
	 * Returns null if not found or other error occured
	 */
	async getUserSession(sessid: string): Promise<UserSession | null> {
		try {
			const result = await this.redisClient.get('sessid:'+sessid);
			if (result == null)
				return null;
			return JSON.parse(result as string) as UserSession;
		}
		catch(e) {
			logger.error(newLogerr(3001, "REDIS_ERR\n Details: " + e));
			return null;
		}
	}


	async getSessionByAuthorizationCode(code: string): Promise<UserSession | null> {
		const key = 'oid4ci:code:' + code;
		try {
			const sessionId = await this.redisClient.get(key) as string;
			if (sessionId == null) {
				return null
			}
			const userSession = await this.getUserSession(sessionId);
			return userSession;
		}
		catch(e) {
			return null
		}
	}

	async getSessionByNonce(nonce: string): Promise<UserSession | null> {
		const key = 'oid4vp:nonce:' + nonce;
		try {
			const sessionId = await this.redisClient.get(key) as string;
			if (sessionId == null) {
				return null
			}
			const userSession = await this.getUserSession(sessionId);
			return userSession;
		}
		catch(e) {
			return null
		}
	}

	/**
	 * 
	 * @param code 'plain code'
	 * @param codeMapValue 
	 */
	async storeAuthorizationCode(code: string, sessionId: string): Promise<Result<null, 'FAILED_STORAGE_ON_REDIS'>> {
		const key = 'oid4ci:code:' + code;	
		try {
			// set expiration time for the session
			await this.redisClient.set(key, sessionId, {
				EX: 1000 // for 100 seconds = 1.5 minutes
			});
			return Ok(null);
		}
		catch(e) {
			return Err('FAILED_STORAGE_ON_REDIS');
		}
	}

	async getSessionByAccessToken(accessToken: string): Promise<Result<UserSession, 'REDIS_ERR' | 'KEY_NOT_FOUND'>> {
		const key = 'oid4ci:token:' + accessToken;
		try {
			const sessionId = await this.redisClient.get(key) as string;
			if (!sessionId) {
				return Err('KEY_NOT_FOUND');
			}
			const userSession = await this.getUserSession(sessionId);
			if (!userSession) {
				return Err('KEY_NOT_FOUND');
			}
			return Ok(userSession);
		}
		catch(e) {
			return Err('REDIS_ERR');
		}
	}
	async storeAccessToken(accessToken: string, sessionId: string): Promise<Result<null, 'REDIS_FAILED_TOKEN_STORAGE'>> {
		const key = 'oid4ci:token:'+accessToken;
		try {
			// set expiration time for the session
			await this.redisClient.set(key, sessionId, {
				EX: 10000 // for 100 seconds = 1.5 minutes
			});
			return Ok(null);
		}
		catch(e) {
			return Err('REDIS_FAILED_TOKEN_STORAGE');
		}
	}

	async getSessionByAcceptanceToken(acceptanceToken: string): Promise<Result<UserSession, 'REDIS_ERR' | 'KEY_NOT_FOUND'>> {
		const key = 'oid4ci:acceptance_token:' + acceptanceToken;
		try {
			const sessionId = await this.redisClient.get(key) as string;
			if (!sessionId) {
				return Err('KEY_NOT_FOUND');
			}
			const userSession = await this.getUserSession(sessionId);
			if (!userSession) {
				return Err('KEY_NOT_FOUND');
			}
			return Ok(userSession);
		}
		catch(e) {
			return Err('REDIS_ERR');
		}
	}


	async storeAcceptanceToken(acceptanceToken: string, sessionId: string): Promise<Result<null, 'REDIS_FAILED_ACCEPTANCE_TOKEN_STORAGE'>> {
		const key = 'oid4ci:acceptance_token:'+acceptanceToken;
		try {
			// set expiration time for the session
			await this.redisClient.set(key, sessionId, {
				EX: 1000000000 // for 100 seconds = 1.5 minutes
			});
			return Ok(null);
		}
		catch(e) {
			return Err('REDIS_FAILED_ACCEPTANCE_TOKEN_STORAGE');
		}
	}

	async getSessionByPreAuthorizedCode(preAuthCode: string, userPin: string): Promise<Result<UserSession, 'REDIS_ERR' | 'KEY_NOT_FOUND'>> {
		const key = 'oid4ci:pre_authorized_code:' + preAuthCode + ":" + userPin;
		try {
			const sessionId = await this.redisClient.get(key) as string;
			if (!sessionId) {
				return Err('KEY_NOT_FOUND');
			}
			const userSession = await this.getUserSession(sessionId);
			if (!userSession) {
				return Err('KEY_NOT_FOUND');
			}
			return Ok(userSession);
		}
		catch(e) {
			return Err('REDIS_ERR');
		}
	}


	async storePreAuthorizedCode(preAuthCode: string, userPin: string, sessionId: string): Promise<Result<null, 'REDIS_FAILED_PRE_AUTH_CODE_STORAGE'>> {
		const key = 'oid4ci:pre_authorized_code:' + preAuthCode + ":" + userPin;
		try {
			// set expiration time for the session
			await this.redisClient.set(key, sessionId, {
				EX: 1000000000 // for 100 seconds = 1.5 minutes
			});
			return Ok(null);
		}
		catch(e) {
			return Err('REDIS_FAILED_PRE_AUTH_CODE_STORAGE');
		}
	}
}


export const redisModule = new RedisModule();