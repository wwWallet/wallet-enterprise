import 'reflect-metadata';
import { CredentialPool } from './interfaces';
import { injectable } from 'inversify';
import { SupportedCredentialProtocol } from '../lib/CredentialIssuerConfig/SupportedCredentialProtocol';

export type PoolItem = {
	rawCredential:  any
	supportedCredential: SupportedCredentialProtocol;
	acceptance_token: string;
}



// Note: one user cannot get with the same access token credentials with same supported_credential_identifier
// hence we chose the following key
// key: "urn:cred_pool_pending:deferred:<access_token>:<supported_credential_identifier>"
const pendingCredentialsPoolDeferred = new Map<string, PoolItem>();


// key: "urn:cred_pool_ready:deferred:<acceptance_token>"
const readyCredentialsPoolDeferred = new Map<string, PoolItem>();

// key: "urn:cred_pool_ready:in_time:<access_token>:<supported_credential_identifier>"
const readyCredentialsPoolInTime = new Map<string, PoolItem>();

@injectable()
export class CredentialPoolService implements CredentialPool {


	// store functions
	async storeInPendingCredentialsPoolDeferred(access_token: string, supported_credential_identifier: string, item: PoolItem): Promise<void> {
		const key = `urn:cred_pool_pending:deferred:${access_token}:${supported_credential_identifier}`;
		pendingCredentialsPoolDeferred.set(key, { ...item });
	}


	async storeInReadyCredentialsPoolDeferred(acceptance_token: string, item: PoolItem): Promise<void> {
		const key = `urn:cred_pool_ready:deferred:${acceptance_token}`;
		readyCredentialsPoolDeferred.set(key, { ...item });
	}

	async storeInReadyCredentialsPoolInTime(access_token: string, supported_credential_identifier: string, item: PoolItem): Promise<void> {
		const key = `urn:cred_pool_ready:in_time:${access_token}:${supported_credential_identifier}`;
		console.log("store key in time = ", key)
		readyCredentialsPoolInTime.set(key, { ...item });
	}
	
	// getters
	async getFromPendingCredentialsPoolDeferred(access_token: string, supported_credential_identifier: string): Promise<PoolItem | null> {
		const key = `urn:cred_pool_pending:deferred:${access_token}:${supported_credential_identifier}`;
		const item = pendingCredentialsPoolDeferred.get(key);
		return item ? item : null;
	}

	async getFromReadyCredentialsPoolDeferred(acceptance_token: string): Promise<PoolItem | null> {
		const key = `urn:cred_pool_ready:deferred:${acceptance_token}`;
		const item = readyCredentialsPoolDeferred.get(key);
		return item ? item : null;
	}

	async getFromReadyCredentialsPoolInTime(access_token: string, supported_credential_identifier: string): Promise<PoolItem | null> {
		const key = `urn:cred_pool_ready:in_time:${access_token}:${supported_credential_identifier}`;
		console.log("key of ready in time = ", key)
		const item = readyCredentialsPoolInTime.get(key);
		return item ? item : null;
	}


	// movers
	async moveFromPendingToReadyDeferred(access_token: string, supported_credential_identifier: string, rawData: any): Promise<void> {
		const key = `urn:cred_pool_pending:deferred:${access_token}:${supported_credential_identifier}`;
		const pendingCred = pendingCredentialsPoolDeferred.get(key);
		pendingCredentialsPoolDeferred.delete(key);
		if (pendingCred) {
			const key = `urn:cred_pool_ready:deferred:${pendingCred.acceptance_token}`;
			pendingCred.rawCredential.rawData = rawData;
			pendingCred.rawCredential.readyToBeSigned = true;
			readyCredentialsPoolDeferred.set(key, pendingCred);
		}
	}


}