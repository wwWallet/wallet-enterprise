import { JWK } from "jose";
import { DidKeyResolverService } from "./interfaces";
import { injectable } from "inversify";
import 'reflect-metadata';
import { getPublicKeyFromDid } from "@gunet/ssi-sdk";


@injectable()
export class EBSIDidKeyResolverService implements DidKeyResolverService {
	async getPublicKeyJwk(did: string): Promise<JWK> {
		return getPublicKeyFromDid(did);
	}

}