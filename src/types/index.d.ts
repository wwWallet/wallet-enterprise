import { Language } from "./language.type";
import { UserSession } from "../RedisModule";
// to make the file a module and avoid the TypeScript error
export {}

declare global {
  namespace Express {
    export interface Request {
      lang: Language;
			userSession?: UserSession;
    }
  }
}