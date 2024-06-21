import axios from "axios"
import config from "../../config"

const axiosConfiguration = {
	headers: {
		authorization: `Basic ${config.crl.credentials.basicToken}`
	}
};

export const CredentialStatusList = {
	get: async (): Promise<{ crl: { id: number, revocation_date: Date }[] }> => {
		const res = await axios.get(config.crl.url);
		return res.data;
	},

	insert: async (): Promise<{ id: number }> => {
		const result = await axios.post(config.crl.url + '/insert', {}, axiosConfiguration);
		const { id } = result.data;
		return { id };
	},

	revoke: async (credential_id: number): Promise<void> => {
		await axios.post(config.crl.url + '/revoke', { credential_id: credential_id }, axiosConfiguration);
	},

}