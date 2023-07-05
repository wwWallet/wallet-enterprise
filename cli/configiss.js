#!/usr/bin/env node

const yargs = require('yargs');
require('dotenv').config();
const knex = require('knex');

const db = knex({
  client: 'mysql2',
  connection: {
    host: process.env.DB_HOST,
		port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  }
});

yargs
  .command('client', '', (clientYargs) => {
		clientYargs.command('create', 'Create client', (createClientYargs) => {
			createClientYargs
				.option('client_id', {
					description: "Give client id",
					type: "string",
					demandOption: true
				})
				.option('client_secret', {
					description: "Give client secret",
					type: "string",
					demandOption: true
				})
				.option('redirect_uri', {
					description: "Give redirect uri for user",
					type: "string",
					demandOption: true
				})
				.option('jwks_uri', {
					description: "Give jwks uri for this specific client in order to verify the assertions (OIDC)",
					type: "string",
					demandOption: false
				})
			createClient({...createClientYargs.argv})
		})
  })
  .help()
  .argv;



async function createClient({client_id, client_secret, redirect_uri, jwks_uri}) {
	console.log("Client id = ", client_id)
	console.log("Client secret = ", client_secret)

	db("client")
  .insert({client_id, client_secret, redirect_uri, jwks_uri})
  .then((result) => {
    // Process the insertion result
    console.log('New client inserted successfully');
		db.destroy()
		return;
  })
  .catch((error) => {
    // Handle insertion errors
    console.error('Error inserting new row:', error);
		db.destroy()

  });
	return;
}

