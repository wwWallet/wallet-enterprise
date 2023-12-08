import { JWK } from "jose";
import { DidKeyResolverService } from "./interfaces";
import { injectable } from "inversify";
import 'reflect-metadata';
import axios from "axios";
import config from "../../config";





@injectable()
export class W3CDidKeyResolverService implements DidKeyResolverService {
	async getPublicKeyJwk(did: string): Promise<JWK> {
		
		const doc = (await axios.get(`${config.didResolverServiceUrl}/${did}`)).data;
		if (doc.didDocument == null) {
			throw new Error("Failed to resolve the generated DID");
		}
		
		if (!doc.didDocument || !doc.didDocument.verificationMethod || !doc.didDocument.verificationMethod[0]) {
			throw new Error("DID could not be resolved")
		}

		const publicKeyJwk = doc.didDocument.verificationMethod[0].publicKeyJwk as JWK;
		return publicKeyJwk;
	}
}