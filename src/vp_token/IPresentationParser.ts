
export interface IPresentationParser {
	parse(presentationRawFormat: string | object): Promise<{ credentialImage: string, credentialPayload: any } | { error: "PARSE_ERROR" }>;
}