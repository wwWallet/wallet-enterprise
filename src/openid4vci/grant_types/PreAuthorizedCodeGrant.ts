import AppDataSource from "../../AppDataSource";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { TokenRequestBodySchemaForPreAuthorizedCodeGrantType, TokenResponseSchemaType } from "../../types/oid4vci";
import { generateAccessToken } from "../utils/generateAccessToken";


export async function preAuthorizedCodeGrantTokenEndpoint(body: TokenRequestBodySchemaForPreAuthorizedCodeGrantType): Promise<TokenResponseSchemaType> {
	const state = await AppDataSource.getRepository(AuthorizationServerState).createQueryBuilder("state")
		.where("pre_authorized_code = :code", { code: body["pre-authorized_code"] })
		.getOne();

	if (!state) {
		throw new Error(`No authorization server state was found for authorization code ${body["pre-authorized_code"]}`);
	}
	return generateAccessToken(state);
}
