import { PresentationDefinitionType } from "@wwwallet/ssi-sdk";
import { JWK, JWTHeaderParameters } from "jose";
import { Request , Response} from 'express'
import { OpenidForPresentationsConfiguration } from "./types/OpenidForPresentationsConfiguration.type";
import 'reflect-metadata';
import { AuthorizationDetailsSchemaType, CredentialSupported, GrantType } from "../types/oid4vci";
import { CredentialIssuersRepository } from "../lib/CredentialIssuersRepository";
import { PresentationClaims } from "../entities/VerifiablePresentation.entity";

export interface CredentialSigner {
	sign(payload: any, headers: JWTHeaderParameters | {}, disclosureFrame: any | undefined): Promise<{ jws: string }>;
	getPublicKeyJwk(): Promise<{ jwk: JWK }>;
	getDID(): Promise<{ did: string }>;
}

export interface OpenidForCredentialIssuingAuthorizationServerInterface {
	generateCredentialOfferURL(ctx: { req: Request, res: Response }, credentialSupported: CredentialSupported, grantType: GrantType, issuerState?: string): Promise<{ url: URL, user_pin_required?: boolean, user_pin?: string }>;
	metadataRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	
	authorizationRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	metadataRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	authorizationRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;

	sendAuthorizationResponse(ctx: { req: Request, res: Response }, bindedUserSessionId: number, authorizationDetails?: AuthorizationDetailsSchemaType): Promise<void>;

	tokenRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	// credentialRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	// batchCredentialRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
}



export interface OpenidForPresentationsReceivingInterface {
	metadataRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;

	

	generateAuthorizationRequestURL(ctx: { req: Request, res: Response }, presentationDefinition: object, directPostEndpoint?: string): Promise<{ url: URL; stateId: string }>;
	getPresentationDefinitionHandler(ctx: { req: Request, res: Response }): Promise<void>;
	getPresentationByState(state: string): Promise<{ status: boolean, presentationClaims?: PresentationClaims, rawPresentation?: string }>;
	getPresentationById(id: string): Promise<{ status: boolean, presentationClaims?: PresentationClaims, rawPresentation?: string }>;
	
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



export interface DidKeyResolverServiceInterface {
	getPublicKeyJwk(did: string): Promise<JWK>;
}

export interface CredentialIssuersConfiguration {
	registeredCredentialIssuerRepository(): CredentialIssuersRepository;
	registeredClients(): { client_id: string; friendlyName: string; redirectUri: string; }[];
	defaultCredentialIssuerIdentifier(): string | null;
}