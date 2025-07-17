import axios from "axios";

export async function urlToDataUrl(url: string): Promise<string> {
	const response = await axios.get(url, { responseType: "arraybuffer" });
	const contentType = response.headers["content-type"] || "image/jpeg";
	const base64 = Buffer.from(response.data, "binary").toString("base64");
	const dataUrl = `data:${contentType};base64,${base64}`;
	return dataUrl;
}
