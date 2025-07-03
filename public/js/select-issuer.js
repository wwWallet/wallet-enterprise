document.forms.issuer.onsubmit = function (event) {

	const formData = new FormData(document.forms.issuer);
	const issuer = formData.get('issuer');
	if (issuer === "" || issuer === null) {
		event.preventDefault();
		console.log('No Issuer');
		popupAlert('no-issuer');
		return;
	}
	if (issuer !== "uoa") {
		event.preventDefault();
		console.log('Invalid Issuer');
		popupAlert('invalid-issuer');
		return;
	}

}
