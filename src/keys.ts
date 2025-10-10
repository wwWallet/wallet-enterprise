import fs from 'fs';
import path from "path";
import { JWK } from 'jose';
import { bls12_381 } from '@noble/curves/bls12-381';
import { exportIssuerPrivateJwk, exportIssuerPublicJwk } from 'wallet-common/dist/jwp';


const bbsPrivateKeyPath = path.join(__dirname, "../../keys/bbs-private.jwk");
const bbsPublicKeyPath = path.join(__dirname, "../../keys/bbs-public.jwk");

export function getOrGenerateBbsPrivateKey(): JWK & { kty: 'EC', crv: 'BLS12381G2', d: string } {
	try {
		const content = fs.readFileSync(bbsPrivateKeyPath, 'utf-8');
		const jwk = JSON.parse(content.toString()) as any;
		if (jwk.kty === 'EC' && jwk.crv === 'BLS12381G2' && (typeof jwk.d === 'string')) {
			return jwk;
		} else {
			throw new Error("Invalid BBS private key: " + bbsPrivateKeyPath);
		}
	} catch (e) {
		if (fs.existsSync(bbsPrivateKeyPath)) {
			throw e;
		} else {
			const sk = bls12_381.fields.Fr.fromBytes(bls12_381.utils.randomSecretKey());
			const jwkPrivate = exportIssuerPrivateJwk(sk, 'experimental/SplitBBSv2.1');
			const jwkPublic = exportIssuerPublicJwk(bls12_381.G2.Point.BASE.multiply(sk), 'experimental/SplitBBSv2.1');
			fs.writeFileSync(bbsPrivateKeyPath, JSON.stringify(jwkPrivate), 'utf-8');
			fs.writeFileSync(bbsPublicKeyPath, JSON.stringify(jwkPublic), 'utf-8');
			return getOrGenerateBbsPrivateKey();
		}
	}
}

export function getBbsPublicKey(): JWK & { kty: 'EC', crv: 'BLS12381G2' } | null {
	if (fs.existsSync(bbsPublicKeyPath)) {
		const content = fs.readFileSync(bbsPublicKeyPath, 'utf-8');
		const jwk = JSON.parse(content.toString()) as any;
		if (jwk.kty === 'EC' && jwk.crv === 'BLS12381G2' && !("d" in jwk)) {
			return jwk;
		} else {
			throw new Error("Invalid BBS public key: " + bbsPrivateKeyPath);
		}
	} else {
		return null;
	}
}

export function getBbsPublicKeyOrFail(): JWK & { kty: 'EC', crv: 'BLS12381G2' } {
	const jwk = getBbsPublicKey();
	if (jwk) {
		return jwk;
	} else {
		throw new Error("BBS public key not initialized: " + bbsPublicKeyPath);
	}
}
