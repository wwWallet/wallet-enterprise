import config from "../../../config";
import { z } from "zod";
import { Request, Response } from "express";
import { EnterpriseCoreSDK, UserInfoProfileResponse } from "../../authorization/authentication/enterprise-core-sdk";
import locale from "../../locale";
import { store } from "../CacheStore";
import { redisModule } from "../../RedisModule";

const vidProfileZodSchema = z.object({
	issuer: z.string(),
	issuanceDate: z.string(),
	schemaName: z.string(),
	claims: z.object({
		personalIdentifier: z.string()
	})
})


// Instantiate the Enterprise Core SDK
export const enterpriseCoreSDK: EnterpriseCoreSDK = {
	presentationDefinitionName: "VIDwithPersonalID",
	enterpriseCoreBaseUrl: config.walletCore.url,
	enterpriseCoreUser: "user",
	enterpriseCoreSecret: "secret",
	callbackUrl: config.url + "/authorization/vid/vidauth",
	store: store,
	authguardCallback: (req: Request, res: Response, next: any, userinfo: UserInfoProfileResponse) => {
		console.log("Userinfo printed from the guard")
		console.dir(userinfo, {depth: null, colors: true})
		const vidProfile = userinfo.profiles.filter(prof => prof.schemaName === "VID").length 
			? userinfo.profiles.filter(prof => prof.schemaName === "VID")[0]
			: null;
		const validationResult = vidProfileZodSchema.safeParse(vidProfile);
		if (!vidProfile || !validationResult.success) {
			return res.render('error', { title: "Error: 3000", lang: req.lang, locale: locale[req.lang] });
		}
		console.log("Extracted personalIdentifier = ", validationResult.data.claims.personalIdentifier);
		if (!req.userSession) {
			return res.render('error', { title: "No session was found", lang: req.lang, locale: locale[req.lang] });
		}

		req.userSession = { 
			...req.userSession,
			additionalData: { 
				...req.userSession?.additionalData,
				ssn: validationResult.data.claims.personalIdentifier
			}
		};
		
		redisModule.storeUserSession(req.userSession.id, req.userSession).then(() => {
			next();

		})
	},
}