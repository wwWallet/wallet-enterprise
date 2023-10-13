import { JWK } from "jose";
import { DidKeyResolverService } from "./interfaces";
import { injectable } from "inversify";
import 'reflect-metadata';
import { didKeyPublicKeyAdapter } from '@wwwallet/ssi-sdk';

@injectable()
export class EBSIDidKeyResolverService implements DidKeyResolverService {
	async getPublicKeyJwk(did: string): Promise<JWK> {
		// this is using EBSI's version of did:key
		return await didKeyPublicKeyAdapter.getPublicKeyJwk(did + '#' + did.split(':')[2]);
	}
}