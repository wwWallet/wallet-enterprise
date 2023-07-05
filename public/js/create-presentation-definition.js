
const schemas = document.querySelectorAll('.Schema');

// Initialize all scopes as disabled
document.querySelectorAll('.Scope').forEach(function (val, key) {
	val.disabled = true
});


// add event listeners for all scopes
for (const schema of schemas) {
	schema.addEventListener('change', function (event) {
		const schemaID = event.target.id;
		const schemaCheckboxValue = event.target.checked;
		console.log(' val = ', schemaCheckboxValue)
		$(`[id^="${schemaID}."]`).map(function () {
			if (schemaCheckboxValue == true) {
				document.getElementById(this.id).disabled = false;
			}
			else {
				document.getElementById(this.id).disabled = true;
				document.getElementById(this.id).checked = false;
			}
			console.log("id = ", this.id)
		})
	})
}

