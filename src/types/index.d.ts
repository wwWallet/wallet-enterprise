import { Language } from "./language.type";
import { AuthorizationServerState } from "../entities/AuthorizationServerState.entity";
// to make the file a module and avoid the TypeScript error
export {}

declare global {
  namespace Express {
    export interface Request {
      lang: Language;
			authorizationServerState: AuthorizationServerState;
    }
  }
}
