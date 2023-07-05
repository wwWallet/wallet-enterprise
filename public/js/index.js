

if (document.getElementById('mainBtn')) {
	document.getElementById('mainBtn').addEventListener('click', (event) => {
		function isMobileBrowser() {
			return /Mobi|Android/i.test(navigator.userAgent);
		}
		
		let DEVICE_TYPE = "MOBILE";
		if (!isMobileBrowser()) {
			DEVICE_TYPE = "DESKTOP"
		}
		const encodedCredentialIssuerIdentifier = encodeURIComponent(document.getElementById('credentialIssuerIdentifier').value)
		window.location.href = "/openid4vci/init/view/" + DEVICE_TYPE + `?issuer=${encodedCredentialIssuerIdentifier}`;
	})
}
