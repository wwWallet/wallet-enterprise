import axios from "axios"
import config from "../../config"

const axiosConfiguration = {
	headers: {
		authorization: `Basic ${config.crl.credentials.basicToken}`
	}
};

export const CredentialStatusList = {
	get: async (): Promise<{ crl: { id: number, personal_identifier: string, revocation_date: Date, issuer_name: string; }[] }> => {
		const res = await axios.get(config.crl.url);
		return res.data;
	},

	insert: async (username: string, personal_identifier: string, issuer_name: string): Promise<{ id: number }> => {
		const result = await axios.post(config.crl.url + '/insert', { username, personal_identifier, issuer_name }, axiosConfiguration);
		const { id } = result.data;
		return { id };
	},

	revoke: async (credential_id: number): Promise<void> => {
		await axios.post(config.crl.url + '/revoke', { credential_id: credential_id }, axiosConfiguration);
	},

	revokeByPersonalIdentifier: async (personal_identifier: string): Promise<void> => {
		await axios.post(config.crl.url + '/revoke', { personal_identifier: personal_identifier }, axiosConfiguration);
	},

}