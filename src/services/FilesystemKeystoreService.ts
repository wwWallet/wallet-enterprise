import { injectable } from "inversify";
import { WalletKeystore } from "./interfaces";
import { SignVerifiableCredentialJWT } from "@gunet/ssi-sdk";
import fs from 'fs';
import path from "path";
import { DidEbsiKeyTypeObject, DidKeyKeyTypeObject, EbsiLegalPersonMethodIdentifier, Identifier, KeyMethodIdentifier, SigningAlgorithm } from "../lib/Identifier";
import { z } from 'zod';
import { JWK, importJWK } from "jose";
import 'reflect-metadata';


const KeyDescriptorSchema = z.object({
	id: z.string(),
	kid: z.string(),
	privateKeyJwk: z.any(),
	publicKeyJwk: z.any()
})

const EbsiLegalPersonMethodIdentifierKeySchema = z.object({
	did: z.string(),
	didVersion: z.literal(1),
	keys: z.object({
		ES256: KeyDescriptorSchema,
		ES256K: KeyDescriptorSchema
	})
})

const KeyIdentifierKeySchema = z.object({
	did: z.string(),
	alg: z.string(),
	key: KeyDescriptorSchema,
})

@injectable()
export class FilesystemKeystoreService implements WalletKeystore {

	constructor(
		private readonly algorithm: SigningAlgorithm = SigningAlgorithm.ES256,

		// this map is indexed using the issuerId
		private identifiers: Map<string, Identifier> = new Map<string, Identifier>()
	) { 
		this.loadWalletsFromFilesystem();
	}

	private loadWalletsFromFilesystem() {
		const directoryPath = path.join(__dirname, '../../../keys');
		const filenameList = fs.readdirSync(directoryPath);
		for (const filename of filenameList) {
			const absoluteFilePath = path.join(directoryPath, filename);
			const issuerIdentifier = filename.split('.')[1];
			const keyJson = JSON.parse(fs.readFileSync(absoluteFilePath, 'utf-8').toString());
			let identifier: Identifier;
			if (EbsiLegalPersonMethodIdentifierKeySchema.safeParse(keyJson).success) {
				identifier = new EbsiLegalPersonMethodIdentifier(keyJson as DidEbsiKeyTypeObject)
			}
			else if (KeyIdentifierKeySchema.safeParse(keyJson).success) {
				identifier = new KeyMethodIdentifier(keyJson as DidKeyKeyTypeObject);
			}
			else {
				throw new Error(`Cannot import keyfile with name "${filename}"`)
			}
			this.identifiers.set(issuerIdentifier, identifier);
		}
	}
	

	public async getAllPublicKeys(): Promise<{ jwks: JWK[] }> {
		const promises = Array.from(this.identifiers.keys()).map((walletId) => this.getPublicKeyJwk(walletId) );
		const publicKeys = await Promise.all(promises);
		return { jwks: publicKeys.map((pk) => pk.jwk) };
	}

	public async getPublicKeyJwk(issuerId: string): Promise<{ jwk: JWK; }> {
		const identifier = this.identifiers.get(issuerId);
		let publicKeyJwk;
		let kid;
		if (!identifier) {
			throw new Error("No identifier was found for issued id " + issuerId);
		}
		if (identifier instanceof EbsiLegalPersonMethodIdentifier) {
			publicKeyJwk = identifier.key?.keys.ES256?.publicKeyJwk as JWK;
			kid = identifier.key?.keys.ES256?.kid;
		}
		else if (identifier instanceof KeyMethodIdentifier) {
			publicKeyJwk = identifier.key?.key.publicKeyJwk as JWK;
			kid = identifier.key?.key.kid;
		}		
		else {
			throw new Error("Invalid identifier instance");
		}
		return { jwk: { ...publicKeyJwk, kid } };
	}


	async signVcJwt(walletId: string, vcjwt: SignVerifiableCredentialJWT<any>): Promise<{ credential: string; }> {
		// throw new Error("Method not implemented.");

		const identifier = this.identifiers.get(walletId);
		if (!identifier) {
			throw new Error("Invalid identifier instance");
		}

		let kid, iss, privateKey, privateKeyJwk;
		
		if (identifier instanceof EbsiLegalPersonMethodIdentifier) {
			kid = identifier.key?.keys.ES256?.kid;
			iss = identifier.key?.did;
			privateKeyJwk = identifier.key?.keys.ES256?.privateKeyJwk as JWK;
		}
		else if (identifier instanceof KeyMethodIdentifier) {
			kid = identifier.key?.key.kid;
			iss = identifier.key?.did;
			privateKeyJwk = identifier.key?.key.privateKeyJwk as JWK;
		}
		else {
			throw new Error("Cannot select identifer");
		}

		privateKey = await importJWK(privateKeyJwk as JWK, this.algorithm)

		const credential = await vcjwt.setProtectedHeader({ 
				alg: this.algorithm,
				kid: kid as string,
				typ: "JWT"
			})
			.setIssuer(iss as string)
			.sign(privateKey);

		return { credential };
	}
	
}