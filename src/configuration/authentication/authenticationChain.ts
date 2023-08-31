import { CONSENT_ENTRYPOINT } from "../../authorization/constants";
import { AuthenticationChainBuilder } from "../../authentication/AuthenticationComponent";
import { LocalAuthenticationComponent } from "./LocalAuthenticationComponent";





export const authChain = new AuthenticationChainBuilder()
	.addAuthenticationComponent(new LocalAuthenticationComponent("1-local", CONSENT_ENTRYPOINT))
	.build();