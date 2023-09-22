import config from "../config";

export const authorizationServerMetadataConfiguration = {
	"issuer": `${config.url}`,
	"authorization_endpoint": `${config.url}/openid4vci/authorize`,
	"token_endpoint": `${config.url}/openid4vci/token`,
	"jwks_uri": `${config.url}/jwks`,
	"scopes_supported": ["openid"],
	"response_types_supported": ["vp_token", "id_token"],
	"response_modes_supported": ["query"],
	"grant_types_supported": ["authorization_code", "pre-authorized_code"],
	"subject_types_supported": ["public"],
	"id_token_signing_alg_values_supported": ["ES256"],
	"request_object_signing_alg_values_supported": ["ES256"],
	"request_parameter_supported": true,
	"request_uri_parameter_supported": true,
	"token_endpoint_auth_methods_supported": ["private_key_jwt"],
	"vp_formats_supported": {
		"jwt_vp": {
			"alg_values_supported": ["ES256"]
		},
		"jwt_vc": {
			"alg_values_supported": ["ES256"]
		}
	},
	"subject_syntax_types_supported": ["did:key"],
	"subject_trust_frameworks_supported": ["ebsi"],
	"id_token_types_supported": [
		"subject_signed_id_token"
	]
}