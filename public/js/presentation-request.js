const form = document.getElementById("PresentationRequestForm");


const path = window.location.pathname;

const pathSegments = path.split('/');

const nonEmptySegments = pathSegments.filter(segment => segment !== '');
const presentationRequestId = nonEmptySegments[nonEmptySegments.length - 1];


const dcApiButtonElement = document.getElementById("open-with-dcapi");
if (dcApiButtonElement !== null) {
	if (!DigitalCredential || !DigitalCredential.userAgentAllowsProtocol("openid4vp")) {
		throw new Error("'openid4vp' is not a supported protocol for DC API");
	}
	const authorizationRequestUrlElement = document.getElementById("authorizationRequestURL");
	if (authorizationRequestUrlElement !== null) {
		const authorizationRequestUrl = new URL(authorizationRequestUrlElement.value);
		const [request_uri, _] = [
			authorizationRequestUrl.searchParams.get('request_uri'),
			authorizationRequestUrl.searchParams.get('client_id'),
		];
		fetch(request_uri, {
			method: 'GET',
		}).then((response) => {
			if (!response.ok) {
				throw new Error(`HTTP error with status ${response.status}`);
			}
			return response.text();
		}).then((signedRequest) => {
			dcApiButtonElement.addEventListener("click", async function() {
				const credential = await navigator.credentials.get({
					digital: {
						requests: [{
							protocol: 'openid4vp',
							data: { request: signedRequest },
						}]
					},
				});
				const jwe = credential.data.response;
				console.log("Received encrypted response: ", jwe);

				const verificationResponse = await fetch('/verification/direct_post', {
					method: 'POST',
					headers: { "Content-Type": "application/x-www-form-urlencoded" },
					body: new URLSearchParams({ response: jwe }),
				}).then((response) => {
					return response.json();
				}).catch((e) => {
					console.error(e);
					return null;
				});
				if (!verificationResponse) {
					console.log("Verification failed");
					return;
				}
				const { redirect_uri } = verificationResponse;
				if (!redirect_uri) {
					console.log("'redirect_uri' is missing from verification response");
				}
				window.location.href = redirect_uri;
			});
		})

	}

}


setInterval(() => {
	fetch('/verifier/public/definitions/presentation-request/status/' + presentationRequestId, {
			method: 'GET',
		}).then((response) => {
			if (!response.ok) {
				throw new Error(`HTTP error with status ${response.status}`);
			}
			return response.json();
		})
		.then((data) => {
			const { url } = data;
			if (url) {
				window.location.href = url;
			}
		})
		.catch((err) => {
			console.error(err);
		});
}, 3000);
