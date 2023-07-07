import { NextFunction, Router, Request, Response } from "express";
import { consent } from "./consentPage";
import session from 'express-session';
import { addLocalAuthMethod } from "./authentication/addLocalAuthMethod";
import { store } from "../configuration/CacheStore";
import config from "../../config";
import passport from "passport";
import { initiateVerificationFlowEndpoint, verificationCallbackEndpoint, vidAuthGuard } from "./authentication/enterprise-core-sdk";
import { enterpriseCoreSDK } from "../configuration/authentication/enterprise-core-sdk-configuration";
import locale from "../locale";






const authorizationRouter = Router();
authorizationRouter.use(session({
  secret: config.appSecret,
  resave: false,
  saveUninitialized: false,
  store,
}));



authorizationRouter.use(passport.initialize());
authorizationRouter.use(passport.session());

// Register the endpoints for the VID authentication
authorizationRouter.get("/login", initiateVerificationFlowEndpoint(enterpriseCoreSDK, async (_req, res, url) => {
	return res.redirect(url);
}));

authorizationRouter.get("/vid/vidauth", verificationCallbackEndpoint(enterpriseCoreSDK), async (_req, res) => {
	return res.redirect("/authorization/local")
});


authorizationRouter.use(vidAuthGuard(enterpriseCoreSDK, async (req, res) => {
	res.render('error', {
		title: "Error",
		lang: req.lang,
		locale: locale[req.lang]
	})
}));

addLocalAuthMethod('/local', authorizationRouter, (res) => {
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