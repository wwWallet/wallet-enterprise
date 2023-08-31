import { Router } from "express";
import { consent } from "./consentPage";
import { authChain } from "../configuration/authentication/authenticationChain";

const authorizationRouter = Router();

authChain.components.map(c => {
	authorizationRouter.use(async (req, res, next) => {
		c.authenticate(req, res, next)
	});
})

authorizationRouter.use('/consent', consent);

export { authorizationRouter };