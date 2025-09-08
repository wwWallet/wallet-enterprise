import { base64url } from 'jose';
import crypto from 'node:crypto';

import { arrayBufferToBase64Url } from '../util/arrayBufferToBase64Url';

export const ExampleTransactionData = () => {
	const webcrypto = crypto.subtle;

	const generateTransactionDataRequestObject = async (descriptorId: string) => {
		return base64url.encode(JSON.stringify({
			type: 'urn:wwwallet:example_transaction_data_type',
			credential_ids: [descriptorId],
		}));
	}

	return {
		generateTransactionDataRequestObject,

		validateTransactionDataResponse: async (exprectedDescriptorId: string, params: { transaction_data_hashes: string[], transaction_data_hashes_alg?: string[] }) => {
			const expectedObjectB64U = await generateTransactionDataRequestObject(exprectedDescriptorId);
			for (const hashB64U of params.transaction_data_hashes) {
				if (!params.transaction_data_hashes_alg || params.transaction_data_hashes_alg.includes('sha-256')) { // sha256 case
					const calculatedHashOfExpectedObject = arrayBufferToBase64Url(await webcrypto.digest('SHA-256', new TextEncoder().encode(expectedObjectB64U)));
					console.log("calculatedHash = ", calculatedHashOfExpectedObject);
					console.log("hashB64U = ", hashB64U);
					if (calculatedHashOfExpectedObject === hashB64U) {
						return true;
					}
				}
			}
			return false;
		}
	}
}

export const TransactionData = (transactionDataType: 'urn:wwwallet:example_transaction_data_type') => {
	switch(transactionDataType) {
		case "urn:wwwallet:example_transaction_data_type":
			return ExampleTransactionData();
		default:
			return null;
	}
}
