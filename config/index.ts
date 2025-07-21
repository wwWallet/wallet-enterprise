
export const config = {
	url: "SERVICE_URL",
	port: "SERVICE_PORT",
	appSecret: "SERVICE_SECRET",
	db: {
		host: "DB_HOST",
		port: "DB_PORT",
		username: "DB_USER",
		password: "DB_PASSWORD",
		dbname: "DB_NAME"
	},
	display: [
		{
			name: "Enterprise wallet",
			locale: "en-US"
		}
	],
	issuanceFlow: {
		skipConsent: false,
		defaultCredentialConfigurationIds: [],
	},
	presentationFlow: {
		response_mode: "direct_post.jwt",
		transaction_data_required: true,
	},
	appType: 'ISSUER', //ISSUER,VERIFIER
	wwwalletURL: "WWWALLET_URL",
	trustedRootCertificates: [],
	clockTolerance: 60,
	siteConfig: {
		"name": "wwWallet Verifier",
		"short_name": "wwWallet Verifier",
		"theme_color": "#4d7e3e",
		"background_color": "#4d7e3e",
	}
}
