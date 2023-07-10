import { CredentialIssuerConfig } from "../lib/CredentialIssuerConfig/CredentialIssuerConfig";
import config from "../../config";
import { VIDSupportedCredential } from "./SupportedCredentialsConfiguration/VIDSupportedCredential";


export const vidIssuer = new CredentialIssuerConfig(
	"vid",
	config.url,
	config.url,
	config.url + "/openid4vci/credential"
);

vidIssuer.addSupportedCredential(new VIDSupportedCredential(vidIssuer));


export const issuersConfigurations = new Map<string, CredentialIssuerConfig>();
issuersConfigurations.set(vidIssuer.credentialIssuerIdentifier, vidIssuer);


