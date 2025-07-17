import { injectable } from "inversify";
import { CredentialDataModel, CredentialDataModelRegistry } from "./interfaces";


@injectable()
export class CredentialDataModelRegistryService implements CredentialDataModelRegistry {
	private dmArray: CredentialDataModel[] = [];

	register(dm: CredentialDataModel): void {
		this.dmArray.push(dm);
	}

	async getImage(rawCredential: any): Promise<{ uri: string; }> {
		let results = await Promise.all(this.dmArray.map(async (dm) => {
			return dm.getImage(rawCredential).catch(() => null);
		}))

		results = results.filter((r) => r != null);

		if (results.length == 0) {
			throw new Error("Couldn't get image");
		}
		return results[0] as { uri: string };
	}

	async getCredentialName(rawCredential: any): Promise<{ name: string; }> {
		let results = await Promise.all(this.dmArray.map(async (dm) => {
			return dm.getCredentialName(rawCredential).catch(() => null);
		}))

		results = results.filter((r) => r != null);

		if (results.length == 0) {
			throw new Error("Couldn't get name");
		}
		return results[0] as { name: string };
	}

	async parse(rawCredential: any): Promise<{ data: any; }> {
		let results = await Promise.all(this.dmArray.map(async (dm) => {
			return dm.parse(rawCredential).catch(() => null);
		}))

		results = results.filter((r) => r != null);

		if (results.length == 0) {
			throw new Error("Couldn't get name");
		}
		return results[0] as { data: string };
	}



}
