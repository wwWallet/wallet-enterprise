import { Router } from "express";
import { verifierPanelAuthChain } from "../configuration/authentication/authenticationChain";
import locale from "../locale";



const verifierRouter = Router();


verifierPanelAuthChain.components.map(c => {
	verifierRouter.use(async (req, res, next) => {
		c.authenticate(req, res, next)
	});
})


verifierRouter.get('/', async (req, res) => {
	res.render('verifier/index.pug', {
		lang: req.lang,
		locale: locale[req.lang]
	})
})

export { verifierRouter };