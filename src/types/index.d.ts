import { Language } from "./language.type";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
import { UserAuthenticationMethod } from "./UserAuthenticationMethod.enum";
// to make the file a module and avoid the TypeScript error
// to make the file a module and avoid the TypeScript error

declare global {
  namespace Express {
    export interface Request {
      lang: Language;
			authorizationServerState: AuthorizationServerState;
    }

  }
}


declare module 'express-session' {
  interface Session {
		authorizationServerStateIdentifier?: number; // keep the id (PK) from the AuthorizationServerState
		authenticationChain: {
			authenticationMethodSelectionComponent?: {
				authentication_method: UserAuthenticationMethod
			},
			clientSelectionComponent?: {
				client_id?: string;
			},
			vidAuthenticationComponent?: {
				family_name?: string;
				given_name?: string;
				birth_date?: string;
				document_number?: string;
			},
			localAuthenticationComponent?: {
				username?: string;
			},
			issuerSelectionComponent?: {
				institutionId?: string;
			},
			inspectPersonalInfoComponent?: {
				proceed?: boolean;
			}
		};
    // Add any other custom properties or methods here
  }
}
