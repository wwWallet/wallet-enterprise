import { AUTHORIZATION_ENTRYPOINT } from "../../authorization/constants";
import { AuthenticationChainBuilder } from "../../authentication/AuthenticationComponent";
import { LocalAuthenticationComponent } from "./LocalAuthenticationComponent";
import { LocalAuthenticationComponent2 } from "./LocalAuthenticationComponent2";





export const authChain = new AuthenticationChainBuilder()
	.addAuthenticationComponent(new LocalAuthenticationComponent("1-local", AUTHORIZATION_ENTRYPOINT))
	.addAuthenticationComponent(new LocalAuthenticationComponent2("2-local", AUTHORIZATION_ENTRYPOINT))
	.build();