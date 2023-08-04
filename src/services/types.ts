import 'reflect-metadata';

const TYPES = {
	FilesystemKeystoreService: Symbol.for("FilesystemKeystoreService"),
	OpenidForPresentationsReceivingService: Symbol.for("OpenidForPresentationsReceivingService"),
	VerifierConfigurationServiceInterface: Symbol.for("VerifierConfigurationServiceInterface"),
	OpenidForCredentialIssuingService: Symbol.for("OpenidForCredentialIssuingService"),
	CredentialPoolService: Symbol.for("CredentialPoolService"),
	CredentialReceivingService: Symbol.for("CredentialReceivingService"),
};

export { TYPES };