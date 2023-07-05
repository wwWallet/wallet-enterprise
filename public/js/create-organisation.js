var queryString = window.location.search;
var urlParams = new URLSearchParams(queryString);

if(urlParams.get('no-organisation-title')) {
	errorFeedback('invalid-title');
}

if(urlParams.get('no-organisation-admin-identifier')) {
	errorFeedback('invalid-identifier');
}

if(urlParams.get('duplicate-title')) {
	errorFeedback('duplicate-title', 3000, 'duplicate');
}

document.forms.organisation.onsubmit = function(event) {

	const formData = new FormData(document.forms.organisation);
	const title = formData.get('title');
	const identifier = formData.get('identifier');

	if(title === null || title === "") {
		event.preventDefault();
		errorFeedback('title');
	}
	if(identifier === null || identifier === "") {
		event.preventDefault();
		errorFeedback('identifier');
	}

}