import { DataSource } from "typeorm";
import { config } from "../config";
import { AuthorizationServerState } from './entities/AuthorizationServerState.entity'
import { RelyingPartyState } from './entities/RelyingPartyState.entity'

// Initialize DB connection
const AppDataSource: DataSource = new DataSource({
    type: "mysql",
    host: config.db.host,
    port: Number(config.db.port),
    username: config.db.username,
    password: config.db.password,
    database: config.db.dbname,
    entities: [AuthorizationServerState, RelyingPartyState],
    synchronize: true
});

export async function initDataSource() {
  let connected = false;

  console.log("Connecting with DB...");
  await AppDataSource.initialize()
    .then(() => {
      console.log("App Data Source has been initialized!");
      connected = true;
    })
    .catch((err) => {
      console.error("Error during Data Source initialization", err);
    });

  // if not connected, then retry in loop
  while (!connected) {
    await new Promise((resolve) => setTimeout(resolve, 3000)).then(async () => {
      await AppDataSource.initialize()
        .then(() => {					
          console.log("App Data Source has been initialized!");
          connected = true;
        })
        .catch((err) => {
          console.error("Error during Data Source initialization", err);
        });
    });
  }
};



export default AppDataSource;