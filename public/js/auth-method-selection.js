document.addEventListener("DOMContentLoaded", function () {
	const dropdown = document.getElementById('authMethodDropdown');
	if (dropdown) {
		const options = Array.from(dropdown.options).filter(option => !option.disabled);
		console.log("Options detected = ", options)
		if (options.length === 1) {
			dropdown.value = options[0].value; // Select the single available option
			document.getElementById('IssuerSelection').submit();
		}
	}
});