import { randomUUID } from "crypto";
import { Request, Response, NextFunction } from "express";
import { redisModule, UserSession } from "../RedisModule";


/**
 * Middleware responsible for assigning the session stored on redis to the req.userSession object
 * @param req 
 * @param res 
 * @param next 
 */
export async function UserSessionMiddleware(req: Request, res: Response, next: NextFunction) {
	const sessid = req.cookies["sessid"];
	console.log('sesid = ', sessid)
	const session = await redisModule.getUserSession(sessid);
	if (!session) {
		const sessid = randomUUID();
		const newUserSession: UserSession = {
			lang: 'en',
			id: sessid,
		}
		await redisModule.storeUserSession(sessid, newUserSession);
		res.cookie('sessid', sessid);
		// console.log("SESS = ", session)
		next();
	}
	else {
		req.userSession = session;

		console.log("SESS = ", session)
		next();
	}
}