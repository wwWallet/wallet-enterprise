import { KeyLike } from "jose";
import { IPublicKeyResolver } from "./IPublicKeyResolver";
import { sdJwtPublicKeyResolverUsingX5CHeader } from "./sdJwtPublicKeyResolverUsingX5CHeader";

export class PublicKeyResolverChain {

	constructor(private resolverList: IPublicKeyResolver[] = [
		sdJwtPublicKeyResolverUsingX5CHeader
	]) { }

	addResolver(p: IPublicKeyResolver): this {
		this.resolverList.push(p);
		return this;
	}

	async resolve(rawPresentation: any, format: string): Promise<{ publicKey: KeyLike, isTrusted: boolean } | { error: "UNABLE_TO_RESOLVE_PUBKEY" }> {
		for (const p of [...this.resolverList].reverse()) {
			const result = await p.resolve(rawPresentation, format);
			if ('error' in result) {
				continue;
			}
			return { ...result };
		}
		return { error: "UNABLE_TO_RESOLVE_PUBKEY" };
	}
}
