import { NextFunction, Request, Response } from "express";
import { Language } from "../types/language.type";


export function LanguageMiddleware(req: Request, res: Response, next: NextFunction) {
	const langCode: Language | undefined = req.cookies["lang"];
	// if not defined, set english as default
	if (langCode == undefined) {
		res.cookie('lang', 'en');
		req.lang = 'en';
		next();
	}
	else {
		req.lang = req.cookies["lang"];
		next();
	}	
}