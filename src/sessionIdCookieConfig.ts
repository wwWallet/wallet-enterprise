import { Response } from "express";
import { config } from "../config";

// @ts-ignore
export const secure = config?.sessionIdCookieConfiguration?.secure ? config.sessionIdCookieConfiguration.secure : false;
// @ts-ignore
export const maxAge = config?.sessionIdCookieConfiguration?.maxAge ? config.sessionIdCookieConfiguration.maxAge : 900000; // 15 mins default

export function addSessionIdCookieToResponse(res: Response, session_id: string) {
	res.cookie('session_id', session_id, {
		maxAge: maxAge,
		httpOnly: true,
		sameSite: 'strict',
		secure: secure,
	});
}
