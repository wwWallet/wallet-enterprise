const locale = {
	en: {
		header: {
			title: "wwWallet Issuer",
			subtitle: "Receive your PID",
		},
		plainHeader: {
			title: "National Authentication Service",
			subtitle: "User Authentication"
		},
		footer: {
			services: "Services",
			documentation: "Documentation",
			adminLogin: "Verifier Panel",
			information: "Information",
			participatingInst: "Participating Institutions",
			termsOfUse: "Terms of Use",
			contact: "Contact",
			web: "Web",
			emailForOrgs: "E-mail for Institutions"
		},
		index: {
			header: "wwWallet Issuer",
			phrase: "I want to receive a",
			proceed: "Proceed",
			heading: "wwWallet Issuer",
			paragraph: "The Demo wwWallet Issuer is a proof-of-concept service designed to issue verifiable credentials (VCs) in SD-JWT or mdoc formats, supporting the wwWallet ecosystem. It provides demonstrative credentials, including Personal Identification (PID), European Health Insurance Card (EHIC), Bachelor Diploma and Power of Representation VCs, strictly for testing purposes (not valid for real-world use).",
			demoText: "This issuer follows OpenID4VCI (draft 14) for credential issuance, implementing the authorization_code grant with scope, client_id, state, and PKCE, and supports OpenID for Verifiable Presentations (draft 21) for secure VC verification. It enables developers and stakeholders to explore interoperability and real-world scenarios in digital identity and trust frameworks.",
			metadata: "The issuer's metadata is available at",
			sdJwtMetadata: "and the JWT VC Issuer Metadata configuration can be found at",
			specs: "The specifications that are partially or fully implemented by wwWallet Issuer are shown below:"
		},
		VIDAuthenticationComponent: {
			title: "Authenticate using Digital Credentials"
		},
		login: {
			title: "Login",
			description: "",
			btnText: "Login",
			error: {
				emptyUsername: "Username is empty",
				emptyPassword: "Password is empty",
				invalidCredentials: "Invalid credentials",
				networkError: "Network error occured",
			}
		},
		AuthenticationMethodComponent: {
			title: "Authentication Method",
			label: "Choose between authenticating via presenting a PID or via a conventional 3rd-party authentication service (e.g., National Authentication Service, Google):",
		},
		personalInfo: {
			title: "Personal Identifiable Information",
			subtitle: "Please review the following personal identifiable information (PII) that has been retrieved for you by the National Authentication Service.",
			acknowledgement: "By continuing, you acknowledge that the information is correct and that you agree with its use for the retrieval of your University Degrees.",
			back: "Back",
			proceed: "Confirm and Proceed",
			given_name: "Given Name",
			family_name: "Family Name",
			ssn: "Social Security Number",
			taxisId: "Tax Identification",
			document_number: "Document Number",
		},
	}
}

export default locale;
