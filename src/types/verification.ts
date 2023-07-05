export interface VerificationResults {
	result: boolean;
	validations: {
		vpFormat: {
			status: boolean;
		},
		presentation: {
			status: boolean;
		},
		credential: {
			status: boolean;
		}
	}
}