import { KeyLike } from "jose";

export interface IPublicKeyResolver {
	resolve(rawPresentation: string | object, format: string): Promise<{ publicKey: KeyLike, isTrusted: boolean } | { error: "UNABLE_TO_RESOLVE_PUBKEY" }>;
}
