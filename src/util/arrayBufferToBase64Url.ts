export function arrayBufferToBase64Url(buffer: any) {
	const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
	const base64Url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	return base64Url;
}
