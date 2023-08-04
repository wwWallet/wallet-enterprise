export enum AuthenticationMechanism {
	OPENID4VP_ID_TOKEN,
	OPENID4VP_VP_TOKEN,
	LOCAL,
}

export const AUTHENTICATION_MECHANISM_USED = AuthenticationMechanism.OPENID4VP_ID_TOKEN;