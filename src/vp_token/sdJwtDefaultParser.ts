import { config } from "../../config";
import { generateDataUriFromSvg } from "../lib/generateDataUriFromSvg";
import {
	HasherAlgorithm,
	HasherAndAlgorithm,
	SdJwt,
} from '@sd-jwt/core'

import base64url from "base64url";
import crypto from 'node:crypto';
import axios from "axios";
import { IPresentationParser } from "./IPresentationParser";


// Encoding the string into a Uint8Array
const hasherAndAlgorithm: HasherAndAlgorithm = {
	hasher: (input: string) => {
		// return crypto.subtle.digest('SHA-256', encoder.encode(input)).then((v) => new Uint8Array(v));
		return new Promise((resolve, _reject) => {
			const hash = crypto.createHash('sha256');
			hash.update(input);
			resolve(new Uint8Array(hash.digest()));
		});
	},
	algorithm: HasherAlgorithm.Sha256
}

export const sdJwtDefaultParser: IPresentationParser = {
	async parse(presentationRawFormat) {
		if (typeof presentationRawFormat != 'string') {
			return { error: "PARSE_ERROR" };
		}

		try {
			let defaultLocale = 'en-US';
			let credentialImage = null;
			let credentialPayload = null;

			if (presentationRawFormat.includes('~')) {
				const parsedCredential = await SdJwt.fromCompact<Record<string, unknown>, any>(presentationRawFormat)
					.withHasher(hasherAndAlgorithm)
					.getPrettyClaims();
				const sdJwtHeader = JSON.parse(base64url.decode(presentationRawFormat.split('.')[0])) as any;
				credentialPayload = parsedCredential;
				console.log("Parsed credential = ", parsedCredential)
				const credentialIssuerMetadata = await axios.get(parsedCredential.iss + "/.well-known/openid-credential-issuer").catch(() => null);
				let fistImageUri;
				if (!credentialIssuerMetadata) {
					console.error("Couldnt get image for the credential " + presentationRawFormat);
				}
				else {
					console.log("Credential issuer metadata = ", credentialIssuerMetadata?.data)
					fistImageUri = Object.values(credentialIssuerMetadata?.data?.credential_configurations_supported).map((conf: any) => {
						if (conf?.vct == parsedCredential?.vct) {
							return conf?.display && conf?.display[0] && conf?.display[0]?.background_image?.uri ? conf?.display[0]?.background_image?.uri : undefined;
						}
						return undefined;
					}).filter((val) => val)[0];
				}

				if (sdJwtHeader?.vctm && sdJwtHeader?.vctm?.display?.length > 0 && sdJwtHeader?.vctm?.display[0][defaultLocale]?.rendering?.svg_templates.length > 0 && sdJwtHeader?.vctm?.display[0][defaultLocale]?.rendering?.svg_templates[0]?.uri) {
					const response = await axios.get(sdJwtHeader?.vctm?.display[0][defaultLocale].rendering.svg_templates[0].uri);
					const svgText = response.data;
					const pathsWithValues: any[] = [];
					const dataUri = generateDataUriFromSvg(svgText, pathsWithValues); // replaces all with empty string
					credentialImage = dataUri;
				}
				else if (sdJwtHeader?.vctm && sdJwtHeader?.vctm?.display?.length > 0 && sdJwtHeader?.vctm?.display[0][defaultLocale]?.rendering?.simple?.logo?.uri) {
					credentialImage = sdJwtHeader?.vctm?.display[0][defaultLocale]?.rendering?.simple?.logo?.uri;
				}
				else if (fistImageUri) {
					credentialImage = fistImageUri;
				}
				else {
					credentialImage = config.url + "/images/card.png";
				}
				return { credentialImage, credentialPayload };
			}

			return { error: "PARSE_ERROR" };
		}
		catch (err) {
			console.error(err);
			return { error: "PARSE_ERROR" };
		}
	},
}