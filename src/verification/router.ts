import { Router } from "express";
import { SKIP_CONSENT } from "../configuration/consent/consent.config";
import { AUTHORIZATION_ENTRYPOINT } from "../authorization/constants";
import { appContainer } from "../services/inversify.config";
import { OpenidForCredentialIssuingService } from "../services/OpenidForCredentialIssuingService";
import { OpenidForPresentationsReceivingService } from "../services/OpenidForPresentationReceivingService";
import config from "../../config";
import { redisModule } from "../RedisModule";



const verificationRouter = Router();

// verificationRouter.get("/authorize", openidForPresentationReceivingService.requestHandler);


// This is the last step before the user is redirected to the authorization response (if SKIP_CONSENT is true)
// or to the AUTHORIZATION_ENTRY point
verificationRouter.post("/direct_post", async (req, res) => {
	const openidForCredentialIssuingService = appContainer.resolve(OpenidForCredentialIssuingService);
	const openidForPresentationReceivingService = appContainer.resolve(OpenidForPresentationsReceivingService);
	let redirected = false;
  (res.redirect as any) = (url: string): void => {
		redirected = true;
		res.statusCode = 302;
		res.setHeader("Location", url);
    // Perform the actual redirect
    res.end();
  };

	
	let userSessionId;
	let verifier_state_id;
	try {
		const { bindedUserSessionId, verifierStateId } = await openidForPresentationReceivingService.responseHandler(req, res);
		userSessionId = bindedUserSessionId;
		verifier_state_id = verifierStateId;
	}
	catch(e) {
		console.error(e);
		return;
	}


	if (redirected) {
		console.log("Already redirected")
		return;
	}
	
	if (SKIP_CONSENT) {
		try {
			if (!userSessionId) {
				const msg = {
					error: "No binded authorization request was found",
					error_description: "On /direct_post endpoint, the authorization request cannot be resolved"
				};
				console.error(msg);
				res.status(400).send(msg);
				return;
			}
			try {
				const userSession = await redisModule.getUserSession(userSessionId);
				if (userSession?.authorizationDetails) {
					await openidForCredentialIssuingService.sendAuthorizationResponse(req, res, userSessionId)
				}
				else {
					await openidForPresentationReceivingService.sendAuthorizationResponse(req, res, verifier_state_id);
				}
			}
			catch(e) {
				const msg = {
					error: "Failed sendAuthorizationResponse()",
					error_description: String(e)
				};
				console.error(msg);
				res.status(400).send(msg);
				return;
			}
			return;
		}
		catch(err) {
			const msg = { error: String(err) };
			console.error(msg);
			res.status(400).send(msg);
			return;
		}

	}
	else { // redirect to entry point for user interaction
		res.redirect(config.url + AUTHORIZATION_ENTRYPOINT)
		return;
	}

	
});

export { verificationRouter };