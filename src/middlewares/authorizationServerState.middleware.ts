import { NextFunction, Request, Response } from "express";
import AppDataSource from "../AppDataSource";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
import config from "../../config";
import { SignJWT, jwtVerify } from "jose";

const alg = 'HS256';
const secret = new TextEncoder().encode(config.appSecret,);

export async function createNewAuthorizationServerState(): Promise<AuthorizationServerState> {
	const newAuthorizationServerState = new AuthorizationServerState();
	return await AppDataSource.getRepository(AuthorizationServerState)
		.save(newAuthorizationServerState);
}

export async function storeAuthorizationServerStateIdToWebClient(res: Response, state_id: number) {
	const jws = await new SignJWT({ state_id })
		.setProtectedHeader({ alg })
		.setIssuedAt()
		.setIssuer(config.url)
		.setAudience(config.url)
		.sign(secret);
	res.cookie("state_jws", jws);
}

export async function clearState(res: Response) {
	res.clearCookie("state_jws");
}

export async function authorizationServerStateMiddleware(req: Request, res: Response, next: NextFunction) {

	if (!req.cookies["state_jws"]) {
		const authorizationServerState = await createNewAuthorizationServerState();
		await storeAuthorizationServerStateIdToWebClient(res, authorizationServerState.id);
		next();
	}
	else {
		const state_jws = req.cookies["state_jws"] as string;
		try {
			const { payload: { state_id } } = await jwtVerify(state_jws, secret);
			let authorizationServerState = await AppDataSource.getRepository(AuthorizationServerState)
				.createQueryBuilder("state")
				.where("state.id = :id", { id: state_id })
				.getOne();
	
			if (!authorizationServerState) {
				authorizationServerState = await createNewAuthorizationServerState();
			}
			req.authorizationServerState = authorizationServerState;
			console.log("State = ", req.authorizationServerState);
			next();
		}
		catch(e) {
			// if verification failed, then create a new state
			const authorizationServerState = await createNewAuthorizationServerState();
			await storeAuthorizationServerStateIdToWebClient(res, authorizationServerState.id);
			next();
		}

	}
}