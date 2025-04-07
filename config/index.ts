
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
	appType: 'ISSUER', //ISSUER,VERIFIER
	wwwalletURL: "WWWALLET_URL",
	trustedRootCertificates: [],
	clockTolerance: 60,
	siteConfig: {
		"name": "ACME",
		"short_name": "ACME",
		"theme_color": "#4d7e3e",
		"background_color": "#4d7e3e",
	}
}