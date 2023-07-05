import path from "path";
import { CredentialIssuerConfig } from "../lib/CredentialIssuerConfig/CredentialIssuerConfig";
import { LegalPersonWallet } from "../lib/LegalPersonWallet.type";
import fs from 'fs';
import config from "../../config";
import { VIDSupportedCredential } from "./SupportedCredentialsConfiguration/VIDSupportedCredential";

const uoaKeysPath = path.join(__dirname, '../../../keys/vid-issuer.keys');
if(!fs.existsSync(uoaKeysPath))
	throw new Error('Keyfile does not exist');

const keysFile = fs.readFileSync(uoaKeysPath, 'utf-8');
const vidIssuerLegalPersonWallet = JSON.parse(keysFile) as LegalPersonWallet;


const legalPersonWallets: LegalPersonWallet[] = [];
legalPersonWallets.push(vidIssuerLegalPersonWallet)


export const vidIssuer = new CredentialIssuerConfig(
	config.url,
	vidIssuerLegalPersonWallet, 
	config.url,
	config.url + "/openid4vci/credential"
);

vidIssuer.addSupportedCredential(new VIDSupportedCredential(vidIssuer));


export const issuersConfigurations = new Map<string, CredentialIssuerConfig>();
issuersConfigurations.set(vidIssuer.credentialIssuerIdentifier, vidIssuer);


