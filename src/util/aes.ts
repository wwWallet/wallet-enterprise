import crypto from 'node:crypto';

const ENC_KEY = crypto.randomBytes(32).toString('hex');
console.log("defining iv")
const IV = crypto.randomBytes(16).toString('hex'); // set random initialisation vector
// ENC_KEY and IV can be generated as crypto.randomBytes(32).toString('hex');



export class AES {
	encrypt(val: string) {
		let cipher = crypto.createCipheriv('aes-256-cbc', ENC_KEY, IV);
		let encrypted = cipher.update(val, 'utf8', 'base64');
		encrypted += cipher.final('base64');
		return encrypted;
	}

	decrypt(encrypted: any) {
		let decipher = crypto.createDecipheriv('aes-256-cbc', ENC_KEY, IV);
		let decrypted = decipher.update(encrypted, 'base64', 'utf8');
		return (decrypted + decipher.final('utf8'));
	}
}
