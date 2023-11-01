import { PresentationDefinitionType, SignVerifiableCredentialJWT } from "@wwwallet/ssi-sdk";
import { JWK, SignJWT } from "jose";
import { Request , Response} from 'express'
import { OpenidForPresentationsConfiguration } from "./types/OpenidForPresentationsConfiguration.type";
import 'reflect-metadata';
import { AuthorizationDetailsSchemaType, CredentialSupported } from "../types/oid4vci";
import { CredentialIssuersRepository } from "../lib/CredentialIssuersRepository";


export interface WalletKeystore {
	getAllPublicKeys(): Promise<{ keys: JWK[] }>;
	getPublicKeyJwk(walletIdentifier: string): Promise<{ jwk: JWK }>;
	signVcJwt(walletIdentifier: string, vcjwt: SignVerifiableCredentialJWT<any>): Promise<{ credential: string }>;
	signJwt(walletIdentifier: string, signjwt: SignJWT, typ: string): Promise<{ jws: string }>
}

export interface OpenidForCredentialIssuingAuthorizationServerInterface {
	generateCredentialOfferURL(ctx: { req: Request, res: Response }, credentialSupported: CredentialSupported): Promise<{ url: URL }>;
	metadataRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	authorizationRequestHandler(rctx: { req: Request, res: Response }): Promise<void>;
	metadataRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	authorizationRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;

	sendAuthorizationResponse(ctx: { req: Request, res: Response }, bindedUserSessionId: number, authorizationDetails?: AuthorizationDetailsSchemaType): Promise<void>;

	tokenRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	// credentialRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	// batchCredentialRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
}



export interface OpenidForPresentationsReceivingInterface {
	metadataRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;

	
	authorizationRequestHandler(ctx: { req: Request, res: Response }, userSessionIdToBindWith?: number): Promise<void>;

	generateAuthorizationRequestURL(ctx: { req: Request, res: Response }, presentation_definition_id: string, directPostEndpoint?: string): Promise<{ url: URL; stateId: string }>;
	getPresentationDefinitionHandler(ctx: { req: Request, res: Response }): Promise<void>;
	getPresentationByState(state: string): Promise<{ status: boolean, presentation?: string }>;
	
	/**
	 * @throws
	 * @param req 
	 * @param res 
	 */
	responseHandler(ctx: { req: Request, res: Response }): Promise<{ verifierStateId: string, bindedUserSessionId?: number, vp_token?: string }>;

	sendAuthorizationResponse(ctx: { req: Request, res: Response }, verifierStateId: string): Promise<void>;

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

export interface CredentialIssuersConfiguration {
	registeredCredentialIssuerRepository(): CredentialIssuersRepository;
	defaultCredentialIssuerIdentifier(): string;
}