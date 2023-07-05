import RedisStore from "connect-redis";
import { redisModule } from "../RedisModule";

export const store = new RedisStore({ client: redisModule.redisClient });
