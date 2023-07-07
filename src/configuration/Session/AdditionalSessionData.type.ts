
/**
 * Provide additional data for a user-session
 */
export type AdditionalSessionData = {
	
	// authentication component variables
	subject?: string; // DID of the holder received from SIOP

	taxisid?: string;
}