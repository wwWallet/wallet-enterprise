import { injectable } from "inversify";
import { OpenidForPresentationsConfiguration } from "../../services/types/OpenidForPresentationsConfiguration.type";
import { authorizationServerMetadataConfiguration } from "../../authorizationServiceConfiguration";
import { config } from "../../../config";
import { VerifierConfigurationInterface } from "../../services/interfaces";
import "reflect-metadata";
import { PresentationParserChain } from "../../vp_token/PresentationParserChain";
import { PublicKeyResolverChain } from "../../vp_token/PublicKeyResolverChain";



@injectable()
export class VerifierConfigurationService implements VerifierConfigurationInterface {
	getPresentationParserChain(): PresentationParserChain {
		return new PresentationParserChain();
	}
	getPublicKeyResolverChain(): PublicKeyResolverChain {
		return new PublicKeyResolverChain();
	}

	getPresentationDefinitions(): any[] {
		return []
	}

	getConfiguration(): OpenidForPresentationsConfiguration {
		return {
			baseUrl: config.url,
			client_id: authorizationServerMetadataConfiguration.authorization_endpoint,
			redirect_uri: config.url + "/verification/direct_post",
			authorizationServerWalletIdentifier: "authorization_server",
		}
	}

}
