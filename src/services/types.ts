import 'reflect-metadata';

const TYPES = {
	FilesystemKeystoreService: Symbol.for("FilesystemKeystoreService"),
	OpenidForPresentationsReceivingService: Symbol.for("OpenidForPresentationsReceivingService"),
	VerifierConfigurationServiceInterface: Symbol.for("VerifierConfigurationServiceInterface"),
	OpenidForCredentialIssuingAuthorizationServerService: Symbol.for("OpenidForCredentialIssuingAuthorizationServerService"),
	CredentialReceivingService: Symbol.for("CredentialReceivingService"),
	CredentialIssuersConfiguration: Symbol.for("CredentialIssuersConfiguration"),
	CredentialIssuersService: Symbol.for("CredentialIssuersService"),
	ExpressAppService: Symbol.for("ExpressAppService"),
	DidKeyResolverService: Symbol.for("DidKeyResolverService")
};

export { TYPES };