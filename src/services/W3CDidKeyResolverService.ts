import { JWK } from "jose";
import { DidKeyResolverService } from "./interfaces";
import { injectable } from "inversify";
import 'reflect-metadata';
import * as ed25519 from "@transmute/did-key-ed25519";


@injectable()
export class W3CDidKeyResolverService implements DidKeyResolverService {
	async getPublicKeyJwk(did: string): Promise<JWK> {
		const result = await ed25519.resolve(did, { accept: 'application/did+json' });
		const verificationMethod = result.didDocument.verificationMethod[0] as any;
		return verificationMethod.publicKeyJwk as JWK;
	}

}