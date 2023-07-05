import path from "path";
import { CredentialIssuerConfig } from "../lib/CredentialIssuerConfig/CredentialIssuerConfig";
import { EdiplomasBlueprint } from "./SupportedCredentialsConfiguration/EdiplomasBlueprint";
import { LegalPersonWallet } from "../lib/LegalPersonWallet.type";
import fs from 'fs';
import config from "../../config";

const uoaKeysPath = path.join(__dirname, '../../../keys/issuer-did.uoa.keys');
if(!fs.existsSync(uoaKeysPath))
	throw new Error('Keyfile does not exist');

const keysFile = fs.readFileSync(uoaKeysPath, 'utf-8');
const uoaLegalPersonWallet = JSON.parse(keysFile) as LegalPersonWallet;


const legalPersonWallets: LegalPersonWallet[] = [];
legalPersonWallets.push(uoaLegalPersonWallet)


const blueprintIDs = ["46", "75"]; // fetched from API


export const uoaIssuer = new CredentialIssuerConfig(
	config.url,
	uoaLegalPersonWallet, 
	config.url,
	config.url + "/openid4vci/credential"
);

for (const bp of blueprintIDs) { // load all blueprints for the UOA issuer
	uoaIssuer.addSupportedCredential(new EdiplomasBlueprint(uoaIssuer, bp))
}



export const issuersConfigurations = new Map<string, CredentialIssuerConfig>();
issuersConfigurations.set(uoaIssuer.credentialIssuerIdentifier, uoaIssuer);


