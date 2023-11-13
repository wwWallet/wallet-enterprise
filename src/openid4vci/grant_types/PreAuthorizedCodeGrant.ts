import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import { TokenResponseSchemaType } from "../../types/oid4vci";
import { generateAccessToken } from "../utils/generateAccessToken";


export async function preAuthorizedCodeGrantTokenEndpoint(state: AuthorizationServerState): Promise<TokenResponseSchemaType> {

	return generateAccessToken(state);
}
