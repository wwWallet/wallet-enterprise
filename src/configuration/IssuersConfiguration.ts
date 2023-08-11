import { CredentialIssuerConfig } from "../lib/CredentialIssuerConfig/CredentialIssuerConfig";
import config from "../../config";
import { CTWalletSamePreAuthorisedSupportedCredential } from "./SupportedCredentialsConfiguration/CTWalletSamePreAuthorised";
import { CTWalletSameInTimeSupportedCredential } from "./SupportedCredentialsConfiguration/CTWalletIntimeSupportedCredential";
import { CTWalletSameDeferredSupportedCredential } from "./SupportedCredentialsConfiguration/CTWalletSameDeferredSupportedCredential";
import { CredentialIssuersMap } from "../lib/CredentialIssuerConfig/CredentialIssuersMap";

export const vidIssuer = new CredentialIssuerConfig(
	"conformant",
	config.url,
	config.url,
	config.url + "/openid4vci/credential",
	config.url + "/openid4vci/batch_credential",
	config.url + "/openid4vci/deferred",
);

// vidIssuer.addSupportedCredential(new VIDSupportedCredential(vidIssuer));
vidIssuer.addSupportedCredential(new CTWalletSameInTimeSupportedCredential(vidIssuer));
vidIssuer.addSupportedCredential(new CTWalletSameDeferredSupportedCredential(vidIssuer));
vidIssuer.addSupportedCredential(new CTWalletSamePreAuthorisedSupportedCredential(vidIssuer));


export const issuersConfigurations = new Map<string, CredentialIssuerConfig>();
issuersConfigurations.set(vidIssuer.credentialIssuerIdentifier, vidIssuer);

export const credentialIssuersMap = new CredentialIssuersMap()
	.addCredentialIssuer(vidIssuer.exportIssuerMetadata().credential_issuer)
	
export const defaultIssuer = vidIssuer; // use this as fallback in case the issuer is not specified



// TODO: Remove before commiting
// setTimeout(async () => {
// 	const sessionId = randomUUID()
// 	const preAuthorizedCode = "1234";
// 	const user_pin = "1234"
// 	// store a standard user session
// 	await redisModule.storeUserSession(sessionId, {
// 		id: sessionId,
// 		"pre-authorized_code": preAuthorizedCode,
// 		grantType: GrantType.PRE_AUTHORIZED_CODE
// 	})

// 	await redisModule.storePreAuthorizedCode(preAuthorizedCode, user_pin, sessionId);

// 	console.log("Stored the standard values")
// 	// store a standard pre-authorized code + user_pin and map it with usersession
// }, 2000)