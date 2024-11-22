import { IPresentationParser } from "./IPresentationParser";
import { sdJwtDefaultParser } from "./sdJwtDefaultParser";

export class PresentationParserChain {

	constructor(private parserList: IPresentationParser[] = [
		sdJwtDefaultParser
	]) { }

	addParser(p: IPresentationParser): this {
		this.parserList.push(p);
		return this;
	}

	async parse(rawPresentation: any): Promise<{ credentialImage: string, credentialPayload: any } | { error: "PARSE_ERROR" }> {
		for (const p of [...this.parserList].reverse()) {
			const result = await p.parse(rawPresentation);
			if ('error' in result) {
				continue;
			}
			return { ...result };
		}
		return { error: "PARSE_ERROR" };
	}
}
