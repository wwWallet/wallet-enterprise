import axios from "axios";

export async function urlToBstr(url: string): Promise<Uint8Array> {
	const response = await axios.get(url, { responseType: "arraybuffer" });
	const arrayBuffer = response.data as ArrayBuffer;
	const bstr = new Uint8Array(arrayBuffer);
	return bstr;
}