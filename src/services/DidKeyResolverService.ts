import { JWK } from "jose";
import { DidKeyResolverServiceInterface } from "./interfaces";
import { injectable } from "inversify";
import 'reflect-metadata';
import { didKeyPublicKeyAdapter } from '@wwwallet/ssi-sdk';

@injectable()
export class DidKeyResolverService implements DidKeyResolverServiceInterface {
	async getPublicKeyJwk(did: string): Promise<JWK> {
		return await didKeyPublicKeyAdapter.getPublicKeyJwk(did + '#' + did.split(':')[2]);
	}
}