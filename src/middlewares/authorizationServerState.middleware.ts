import { NextFunction, Request, Response } from "express";
import AppDataSource from "../AppDataSource";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";

export async function createNewAuthorizationServerState(): Promise<AuthorizationServerState> {
	const newAuthorizationServerState = new AuthorizationServerState();
	return await AppDataSource.getRepository(AuthorizationServerState)
		.save(newAuthorizationServerState);
}

export function storeAuthorizationServerStateIdToWebClient(res: Response, state_id: number) {
	res.cookie("state_id", state_id);
}

export async function authorizationServerStateMiddleware(req: Request, res: Response, next: NextFunction) {

	if (!req.cookies["state_id"]) {
		const authorizationServerState = await createNewAuthorizationServerState();
		storeAuthorizationServerStateIdToWebClient(res, authorizationServerState.id);
		next();
	}
	else {
		const issuer_state_id = parseInt(req.cookies["state_id"]);

		let authorizationServerState = await AppDataSource.getRepository(AuthorizationServerState)
			.createQueryBuilder("state")
			.where("state.id = :id", { id: issuer_state_id })
			.getOne();

		if (!authorizationServerState) {
			authorizationServerState = await createNewAuthorizationServerState();
		}
		req.authorizationServerState = authorizationServerState;
		console.log("State = ", req.authorizationServerState);
		next();
	}
}