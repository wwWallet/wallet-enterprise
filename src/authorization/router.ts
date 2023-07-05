import { NextFunction, Router, Request, Response } from "express";
import { consent } from "./consentPage";
import session from 'express-session';
import { addLocalAuthMethod } from "./authentication/addLocalAuthMethod";
import { store } from "../configuration/CacheStore";
import config from "../../config";
import passport from "passport";






const authorizationRouter = Router();
authorizationRouter.use(session({
  secret: config.appSecret,
  resave: false,
  saveUninitialized: false,
  store,
}));



authorizationRouter.use(passport.initialize());
authorizationRouter.use(passport.session());

addLocalAuthMethod('/login', authorizationRouter, (res) => {
	return res.redirect('/authorization/consent')
	// return res.redirect('/authorization/vid')
});

async function authenticationCheck(req: Request, res: Response, next: NextFunction) {
	if (req.isAuthenticated()) {
		return next();
	}
	else {
		return res.redirect('/authorization/login')
	}
}



authorizationRouter.use(authenticationCheck);


authorizationRouter.use('/consent', consent);

export { authorizationRouter };