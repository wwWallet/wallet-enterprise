import { NextFunction, Request, Response } from "express";
import { Language } from "../types/language.type";
import locale from "../configuration/locale";


export function LanguageMiddleware(req: Request, res: Response, next: NextFunction) {
	const langCode: Language | undefined = req.cookies["lang"];
	if (langCode && Object.keys(locale).includes(langCode)) { // if defined and is supported
		req.lang = req.cookies["lang"];
		next();
	}
	else {
		res.cookie('lang', 'en');
		req.lang = 'en';
		next();
	}
}
