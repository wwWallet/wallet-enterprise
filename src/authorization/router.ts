import { Router } from "express";
import { consent } from "./consentPage";
import session from 'express-session';
import { store } from "../configuration/CacheStore";
import config from "../../config";
import passport from "passport";
import { authChain } from "../configuration/authentication/authenticationChain";






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
// authorizationRouter.get("/login", initiateVerificationFlowEndpoint(enterpriseCoreSDK, async (_req, res, url) => {
// 	return res.redirect(url);
// }));

// authorizationRouter.get("/vid/vidauth", verificationCallbackEndpoint(enterpriseCoreSDK), async (_req, res) => {
// 	return res.redirect("/authorization/local")
// });




// authorizationRouter.use(vidAuthGuard(enterpriseCoreSDK, async (req, res) => {
// 	res.render('error', {
// 		title: "Error",
// 		lang: req.lang,
// 		locale: locale[req.lang]
// 	})
// }));





authChain.components.map(c => {
	authorizationRouter.use(async (req, res, next) => {
		c.authenticate(req, res, next)
	});
})




authorizationRouter.use('/consent', consent);

export { authorizationRouter };