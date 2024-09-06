const form = document.getElementById("PresentationRequestForm");

const path = window.location.pathname;

const pathSegments = path.split('/');

const nonEmptySegments = pathSegments.filter(segment => segment !== '');
const presentationDefinitionId = nonEmptySegments[nonEmptySegments.length - 1];

document.addEventListener("DOMContentLoaded", function() {
	const img = document.getElementById("qr-image");

	img.addEventListener("click", function() {
		img.classList.toggle("expanded");
	});
});

setInterval(() => {
	
	const state = form.elements['state'].value;

	fetch('/verifier/public/definitions/presentation-request/' + presentationDefinitionId, {
			method: 'POST',
			body: JSON.stringify({ state }),
			headers: {
				'Content-Type': 'application/json'
			}
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