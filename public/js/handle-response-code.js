const form = document.getElementById("ResponseCode");

if (window.location.hash.startsWith('#response_code')) {
	console.log("Got response code")
	const response_code = window.location.hash.split('=')[1];
	console.log("response code = ", response_code)
	if (response_code) {
		// Create a hidden input field to send the response_code with the form
		const input = document.createElement('input');
		input.type = 'hidden';
		input.name = 'response_code';  // The name of the form field
		input.value = response_code;
		form.appendChild(input);
	}
}

form.submit();
