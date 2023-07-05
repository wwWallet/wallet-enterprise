import passport from "passport";
import { redisModule } from "../../RedisModule";
import locale from "../../locale";
import { Request, Response } from "express";
import PassportLocal from 'passport-local';


export function addLocalAuthMethod(entrypoint: string, authorizationRouter: any, authenticationCb: (res: Response) => void) {


	// assigns an object to req.userSession if user session exists
	
	const LocalStrategy = PassportLocal.Strategy;
	
	
	const userTable = [
		{ username: "user", password: "secret" }
	]
	
	passport.use(new LocalStrategy(
		function(username, password, done) {
			const user = userTable.filter((user) => user.username == username && user.password == password)[0];
			if (!user) 
				done(null, false);
			else
				done(null, user);
		}
	));
	
	
	
	type LocalAuthSchema = {
		username: string;
		password: string;
	}
	
	passport.serializeUser(function(user, done) {
		const tempUser  = user as LocalAuthSchema;
		done(null, tempUser.username);
	});
	
	passport.deserializeUser(function(username, done) {
		const user = userTable.filter((user) => user.username == username)[0];
		done(null, user);
	});
	
	authorizationRouter.get(entrypoint, async (req: Request, res: Response) => {
		return res.render('issuer/login', {
			title: "Login",
			lang: req.lang,
			locale: locale[req.lang]
		})
	})
	
	authorizationRouter.post('/login', 
		passport.authenticate('local', { failureRedirect: '/authorization/login' }),
		async (req: Request, res: Response) => {
			const user = req.user as LocalAuthSchema;
			console.log("USER = ", user)
			if (req.userSession) {
				req.userSession.additionalData = {
					taxisid: user.username
				}
				console.log("updated user = ", req.userSession)
				await redisModule.storeUserSession(req.userSession.id, req.userSession);
			}
			// return res.redirect('/authorization/vp/example');
			authenticationCb(res);
		}
	);
	
	
	

	
}