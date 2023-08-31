import { PresentationDefinitionType, SignVerifiableCredentialJWT } from "@gunet/ssi-sdk";
import { JWK, SignJWT } from "jose";
import { Request , Response} from 'express'
import { OpenidForPresentationsConfiguration } from "./types/OpenidForPresentationsConfiguration.type";
import 'reflect-metadata';
import { PoolItem } from "./CredentialPoolService";
import { AuthorizationDetailsSchemaType } from "../types/oid4vci";


export interface WalletKeystore {
	getAllPublicKeys(): Promise<{ keys: JWK[] }>;
	getPublicKeyJwk(walletIdentifier: string): Promise<{ jwk: JWK }>;
	signVcJwt(walletIdentifier: string, vcjwt: SignVerifiableCredentialJWT<any>): Promise<{ credential: string }>;
	signJwt(walletIdentifier: string, signjwt: SignJWT, typ: string): Promise<{ jws: string }>
}

export interface OpenidForCredentialIssuingAuthorizationServerInterface {
	metadataRequestHandler(req: Request, res: Response): Promise<void>;
	authorizationRequestHandler(req: Request, res: Response): Promise<void>;

	sendAuthorizationResponse(req: Request, res: Response, bindedUserSessionId: number, authorizationDetails?: AuthorizationDetailsSchemaType): Promise<void>;

	tokenRequestHandler(req: Request, res: Response): Promise<void>;
	// credentialRequestHandler(req: Request, res: Response): Promise<void>;
	// batchCredentialRequestHandler(req: Request, res: Response): Promise<void>;
}



export interface OpenidForPresentationsReceivingInterface {
	metadataRequestHandler(req: Request, res: Response): Promise<void>;

	
	authorizationRequestHandler(req: Request, res: Response, userSessionIdToBindWith?: number): Promise<void>;

	/**
	 * @throws
	 * @param req 
	 * @param res 
	 */
	responseHandler(req: Request, res: Response): Promise<{ verifierStateId: string, bindedUserSessionId?: number }>;

	sendAuthorizationResponse(req: Request, res: Response, verifierStateId: string): Promise<void>;

}

export interface VerifierConfigurationInterface {
	getConfiguration(): OpenidForPresentationsConfiguration;
	getPresentationDefinition(): PresentationDefinitionType;
}



export interface CredentialPool {
	storeInPendingCredentialsPoolDeferred(access_token: string, supported_credential_identifier: string, item: PoolItem): Promise<void>
	storeInReadyCredentialsPoolDeferred(acceptance_token: string, item: PoolItem): Promise<void>
	storeInReadyCredentialsPoolInTime(access_token: string, supported_credential_identifier: string, item: PoolItem): Promise<void>


	getFromPendingCredentialsPoolDeferred(access_token: string, supported_credential_identifier: string): Promise<PoolItem | null>
	getFromReadyCredentialsPoolDeferred(acceptance_token: string): Promise<PoolItem | null>
	getFromReadyCredentialsPoolInTime(access_token: string, supported_credential_identifier: string): Promise<PoolItem | null>

	moveFromPendingToReadyDeferred(access_token: string, supported_credential_identifier: string, rawData: any): Promise<void>
}



export interface CredentialReceiving {
	sendAuthorizationRequest(): Promise<void>;
}

