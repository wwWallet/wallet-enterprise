import { KeyObject } from "crypto";
import { JWK } from "jose";
import { Signer, HasherAndAlg } from "@sd-jwt/types";
import { Request, Response } from "express";
import { OpenidForPresentationsConfiguration } from "./types/OpenidForPresentationsConfiguration.type";
import 'reflect-metadata';
import { SupportedCredentialProtocol } from "../lib/CredentialIssuerConfig/SupportedCredentialProtocol";
import { CredentialView } from "../authorization/types";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
import { PresentationClaims, RelyingPartyState } from "../entities/RelyingPartyState.entity";

export type PresentationInfo = {
	[descriptor_id: string]: Array<string>;
}

export interface CredentialSigner {
	signSdJwtVc(payload: any, headers?: any, disclosureFrame?: any): Promise<{ credential: string }>;
	signMsoMdoc(doctype: string, namespaces: Map<string, Record<string, unknown>>, holderPublicKeyJwk: JWK): Promise<{ credential: string }>;
	getPublicKeyJwk(): Promise<{ jwk: JWK }>;
	key(): Promise<KeyObject>;
	signer(): Signer;
	hasherAndAlgorithm: HasherAndAlg;
	saltGenerator: () => string;
}

export interface OpenidForCredentialIssuingAuthorizationServerInterface {
	generateCredentialOfferURL(ctx: { req: Request, res: Response }, credentialConfigurationIds: string[], issuerState?: string): Promise<{ url: URL, user_pin_required?: boolean, user_pin?: string }>;
	metadataRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;

	authorizationRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	metadataRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	authorizeChallengeRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;

	sendAuthorizationResponse(ctx: { req: Request, res: Response }, bindedUserSessionId: number): Promise<void>;

	nonceRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	tokenRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
	credentialRequestHandler(ctx: { req: Request, res: Response }): Promise<void>;
}



export interface OpenidForPresentationsReceivingInterface {

	getSignedRequestObject(ctx: { req: Request, res: Response }): Promise<any>;
	generateAuthorizationRequestURL(ctx: { req: Request, res: Response }, presentationDefinition: object, sessionId: string, callbackEndpoint?: string): Promise<{ url: URL; stateId: string }>;
	getPresentationBySessionIdOrPresentationDuringIssuanceSession(sessionId?: string, presentationDuringIssuanceSession?: string, cleanupSession?: boolean): Promise<{ status: true, rpState: RelyingPartyState, presentations: unknown[], presentationInfo: PresentationInfo } | { status: false, error: Error }>;
	getPresentationById(id: string): Promise<{ status: boolean, presentationClaims?: PresentationClaims, presentations?: unknown[] }>;
	responseHandler(ctx: { req: Request, res: Response }): Promise<void>;
}


export interface VerifierConfigurationInterface {
	getConfiguration(): OpenidForPresentationsConfiguration;
	getPresentationDefinitions(): any[];
}


export interface CredentialReceiving {
	sendAuthorizationRequest(): Promise<void>;
}



export interface CredentialConfigurationRegistry {
	register(credentialConfiguration: SupportedCredentialProtocol): void;

	getAllRegisteredCredentialConfigurations(): SupportedCredentialProtocol[];

	/**
	 * At the moment, an authorization flow can only return a single credential type.
	 *
	 * This function will get an authorization server state as parameter and use every registered credential configuration to
	 * get the CredentialView. If no credential view is found, the return value will be null
	 * @param authorizationServerState
	 */
	getCredentialView(authorizationServerState: AuthorizationServerState): Promise<CredentialView | null>;

	/**
 * At the moment, an authorization flow can only return a single credential type.
 *
 * This function will get an authorization server state as parameter and use every registered credential configuration to
 * get the raw credential response. If the authorizationServerState data is not sufficient the return value will be null
 * @param authorizationServerState
 */
	getCredentialResponse(authorizationServerState: AuthorizationServerState, credentialRequest: Request, holderPublicKeyToBind: JWK): Promise<{
		credential?: unknown;
		error?: Error;
	} | null>;
}

export interface CredentialDataModel {
	getImage(rawCredential: any): Promise<{ uri: string }>;
	getCredentialName(rawCredential: any): Promise<{ name: string }>;
	parse(rawCredential: any): Promise<{ data: any }>;
}

export interface CredentialDataModelRegistry extends CredentialDataModel {
	register(dm: CredentialDataModel): void;
}
