document.forms.AuthenticationMethod.onsubmit = function (event) {

	const formData = new FormData(document.forms.AuthenticationMethod);
	const auth_method = formData.get('auth_method');
	if (auth_method === "" || auth_method === null) {
		event.preventDefault();
		console.log('No client');
		popupAlert('no-issuer');
		return;
	}
}