import { Router } from "express";
import { consent } from "./consentPage";
import session from 'express-session';
import { initiateVerificationFlowEndpoint, verificationCallbackEndpoint, vidAuthGuard } from "./authentication/enterprise-core-sdk";
import { enterpriseCoreSDK } from "../configuration/authentication/enterprise-core-sdk-configuration";
import { store } from "../configuration/CacheStore";
import locale from "../locale";
import config from "../../config";






const authorizationRouter = Router();
authorizationRouter.use(session({
  secret: config.appSecret,
  resave: false,
  saveUninitialized: false,
  store,
}));



// authorizationRouter.use(passport.initialize());
// authorizationRouter.use(passport.session());

// addLocalAuthMethod('/login', authorizationRouter, (res) => {
// 	// return res.redirect('/authorization/consent')
// 	return res.redirect('/authorization/vid')
// });

// async function authenticationCheck(req: Request, res: Response, next: NextFunction) {
// 	if (req.isAuthenticated()) {
// 		return next();
// 	}
// 	else {
// 		return res.redirect('/authorization/login')
// 	}
// }


authorizationRouter.get("/login", async (req, res) => {
	res.render('issuer/vid-login-page', {
		title: "Login",
		lang: req.lang,
		locale: locale[req.lang]
	})
})

// Register the endpoints for the VID authentication
authorizationRouter.get("/vid/init", initiateVerificationFlowEndpoint(enterpriseCoreSDK, async (_req, res, url) => {
	return res.redirect(url);
}));

authorizationRouter.get("/vid/vidauth", verificationCallbackEndpoint(enterpriseCoreSDK), async (_req, res) => {
	return res.redirect("/authorization/consent")
});


// authorizationRouter.use(authenticationCheck);
authorizationRouter.use(vidAuthGuard(enterpriseCoreSDK, async (req, res) => {
	res.render('error', {
		title: "Error",
		lang: req.lang,
		locale: locale[req.lang]
	})
}));

authorizationRouter.use('/consent', consent);

export { authorizationRouter };