import { Err, Ok, Result } from "ts-results";
import { Column, Entity, PrimaryGeneratedColumn, Repository } from "typeorm";
import AppDataSource from "../AppDataSource";
import config from "../../config";


@Entity({ name: "client" })
class ClientEntity {
  @PrimaryGeneratedColumn()
  id: number = -1;


	@Column({ nullable: true })
	client_id?: string = undefined;
	
	@Column({ nullable: true })
	client_secret?: string = undefined;

	@Column({ nullable: false })
	redirect_uri: string = config.walletClientUrl;


	@Column({ nullable: true })
	jwks_uri?: string = undefined; // used for client assertions (Token Endpoint client authentication)
}

type CreateClient = {
	client_id: string;
	client_secret: string;
	redirect_uri: string;
	jwks_uri: string;
}


enum CreateClientErr {
	ALREADY_EXISTS = "ALREADY_EXISTS"
}

enum GetClientErr {
	NOT_FOUND = "NOT_FOUND",
	DB_ERR = "DB_ERR"
}

const clientRepository: Repository<ClientEntity> = AppDataSource.getRepository(ClientEntity);




async function createOpenid4vciClient(createClient: CreateClient) {
	try {
		await AppDataSource
			.createQueryBuilder()
			.insert()
			.into(ClientEntity).values([
				{ ...createClient }
			])
			.execute();
		return Ok({});
	}
	catch(e) {
		console.log(e);
		return Err(CreateClientErr.ALREADY_EXISTS);
	}
}

async function getOpenid4vciClientByClientId(client_id: string): Promise<Result<ClientEntity, GetClientErr>> {
	try {
		const client = await clientRepository 
			.createQueryBuilder("client")
			.where("client.client_id = :client_id", { client_id })
			.getOne();

		if (!client) return Err(GetClientErr.NOT_FOUND);
		return Ok(client);
	}
	catch(e) {
		console.log(e);
		return Err(GetClientErr.DB_ERR);
	}
}

async function getOpenid4vciClientByClientIdAndSecret(client_id: string, client_secret: string): Promise<Result<ClientEntity, GetClientErr>> {
	try {
		const client = await clientRepository 
			.createQueryBuilder("client")
			.where("client.client_id = :client_id and client.client_secret = :client_secret", { client_id, client_secret})
			.getOne();

		if (!client) return Err(GetClientErr.NOT_FOUND);
		return Ok(client);
	}
	catch(e) {
		console.log(e);
		return Err(GetClientErr.DB_ERR);
	}
}



export {
	ClientEntity,
	createOpenid4vciClient,
	getOpenid4vciClientByClientId,
	getOpenid4vciClientByClientIdAndSecret
}