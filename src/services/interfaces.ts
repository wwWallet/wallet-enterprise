import { PresentationDefinitionType, SignVerifiableCredentialJWT } from "@wwwallet/ssi-sdk";
import { JWK, SignJWT } from "jose";
import { Request , Response} from 'express'
import { OpenidForPresentationsConfiguration } from "./types/OpenidForPresentationsConfiguration.type";
import 'reflect-metadata';
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
	getPresentationDefinitions(): PresentationDefinitionType[];
}


export interface CredentialReceiving {
	sendAuthorizationRequest(): Promise<void>;
}



export interface DidKeyResolverService {
	getPublicKeyJwk(did: string): Promise<JWK>;
}