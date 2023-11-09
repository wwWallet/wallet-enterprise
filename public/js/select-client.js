document.forms.client.onsubmit = function (event) {

	const formData = new FormData(document.forms.client);
	const client_id = formData.get('client_id');
	if (client_id === "" || client_id === null) {
		event.preventDefault();
		console.log('No client');
		popupAlert('no-issuer');
		return;
	}
}