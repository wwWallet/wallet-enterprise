import { X509Certificate } from "crypto";

export async function verifyCertificateChain(rootCert: string, pemCertChain: string[]) {
	const x509TrustAnchor = new X509Certificate(rootCert);
	const isLastCertTrusted = new X509Certificate(pemCertChain[pemCertChain.length - 1]).verify(x509TrustAnchor.publicKey);
	if (!isLastCertTrusted) {
		return false;
	}
	for (let i = 0; i < pemCertChain.length; i++) {
		if (pemCertChain[i + 1]) {
			const isTrustedCert = new X509Certificate(pemCertChain[i]).verify(new X509Certificate(pemCertChain[i + 1]).publicKey);
			if (!isTrustedCert) {
				return false;
			}
		}
	}
	return true;
}
