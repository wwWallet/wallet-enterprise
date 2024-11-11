const form = document.getElementById("PresentationRequestForm");


const path = window.location.pathname;

const pathSegments = path.split('/');

const nonEmptySegments = pathSegments.filter(segment => segment !== '');
const presentationDefinitionId = nonEmptySegments[nonEmptySegments.length - 1];

setInterval(() => {
	
	fetch('/verifier/public/definitions/presentation-request/status/' + presentationDefinitionId, {
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


