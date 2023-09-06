import { randomUUID } from 'crypto';
import { NextFunction, Request, Response } from 'express';
import locale from '../configuration/locale';

export function csrfMiddlewareGenerate(req: Request, res: Response, next: NextFunction) {
	req.csrfToken = () => {
		const token = randomUUID();
		res.cookie("csrf_token", token);
		return token;
	}
	next();

}

export function csrfMiddlewareCheck(req: Request, res: Response, next: NextFunction) {
	const csrfTokenFromBody = String(req.body["csrf-token"]);
	const csrfTokenFromCookies = String(req.cookies["csrf_token"]);

	if (csrfTokenFromCookies !== csrfTokenFromBody) {
		res.render('error', {
			code: 3006,
			msg: "CSRF token error",
			lang: req.lang,
			locale: locale[req.lang]
		})
		return;
	}
	next();
}
