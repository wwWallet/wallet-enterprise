import { NextFunction, Request, Response } from "express";
import AppDataSource from "../AppDataSource";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";

// const alg = 'HS256';
// const secret = new TextEncoder().encode(config.appSecret,);

export async function createNewAuthorizationServerState(ctx: { req: Request, res: Response }): Promise<AuthorizationServerState> {
	const newAuthorizationServerState = new AuthorizationServerState();
	const result = await AppDataSource.getRepository(AuthorizationServerState)
		.save(newAuthorizationServerState);
	ctx.req.authorizationServerState = result;
	ctx.req.session.authorizationServerStateIdentifier = result.id
	return result;
}

// export async function storeAuthorizationServerStateIdToWebClient(ctx: { req: Request, res: Response }, state_id: number) {
// 	const jws = await new SignJWT({ state_id })
// 		.setProtectedHeader({ alg })
// 		.setIssuedAt()
// 		.setIssuer(config.url)
// 		.setAudience(config.url)
// 		.sign(secret);
// 	ctx.res.cookie("state_jws", jws);
// }

// export async function clearState(res: Response) {
// 	res.clearCookie("state_jws");
// }

export async function authorizationServerStateMiddleware(req: Request, _res: Response, next: NextFunction) {
	if (req.session.authorizationServerStateIdentifier) {
		const result = await AppDataSource.getRepository(AuthorizationServerState)
			.createQueryBuilder("state")
			.where("state.id = :id", { id: req.session.authorizationServerStateIdentifier })
			.getOne();
		if (result) {
			req.authorizationServerState = result;
		}
	}
	next();
}
// export async function authorizationServerStateMiddleware(req: Request, res: Response, next: NextFunction) {

// 	if (!req.cookies["state_jws"]) {
// 		const authorizationServerState = await createNewAuthorizationServerState();
// 		await storeAuthorizationServerStateIdToWebClient({req, res}, authorizationServerState.id);
// 		next();
// 	}
// 	else {
// 		const state_jws = req.cookies["state_jws"] as string;
// 		try {
// 			const { payload: { state_id } } = await jwtVerify(state_jws, secret);
// 			let authorizationServerState = await AppDataSource.getRepository(AuthorizationServerState)
// 				.createQueryBuilder("state")
// 				.where("state.id = :id", { id: state_id })
// 				.getOne();

// 			if (!authorizationServerState) {
// 				authorizationServerState = await createNewAuthorizationServerState();
// 			}
// 			req.authorizationServerState = authorizationServerState;
// 			next();
// 		}
// 		catch(e) {
// 			// if verification failed, then create a new state
// 			const authorizationServerState = await createNewAuthorizationServerState();
// 			await storeAuthorizationServerStateIdToWebClient({req, res}, authorizationServerState.id);
// 			next();
// 		}

// 	}
// }
