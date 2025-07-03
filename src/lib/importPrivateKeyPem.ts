import { importPKCS8 } from "jose";

export async function importPrivateKeyPem(privateKeyPEM: string, algorithm: string) {
	try {
		const privateKey = await importPKCS8(privateKeyPEM, algorithm);
		return privateKey;
	} catch (err) {
		console.error('Error importing private key:', err);
	}
}
