document.addEventListener("DOMContentLoaded", () => {
	const typeDropdown = document.getElementById("type");
	const attributesContainer = document.getElementById("attributes-container");
	const dcqlQuery = JSON.parse(document.querySelector('script[src="/js/configurable-presentation.js"]').dataset.dcqlQuery);

	const form = document.querySelector("form");
	const dcqlQueryInput = document.getElementById("dcql-query-input");

	function getCredentialByType(type) {
		return dcqlQuery.credentials.find(cred =>
			(type === "sd-jwt" && cred.format === "dc+sd-jwt") ||
			(type === "mdoc" && cred.format === "mso_mdoc")
		);
	}

	function renderFields(type) {
		attributesContainer.innerHTML = "";
		const credential = getCredentialByType(type);
		if (!credential) return;

		(credential.claims || []).forEach((claim, idx) => {
			const label = claim.path.join(".");
			const value = claim.path.join(".");
			const fieldWrapper = document.createElement("div");
			fieldWrapper.classList.add("checkbox-wrapper");

			const input = document.createElement("input");
			input.type = "checkbox";
			input.name = "attributes[]";
			input.value = value;
			input.id = `attr-${idx}`;

			const labelElement = document.createElement("label");
			labelElement.htmlFor = input.id;
			labelElement.textContent = label;
			input.addEventListener("change", updateRequestButtonState);
			fieldWrapper.appendChild(input);
			fieldWrapper.appendChild(labelElement);
			attributesContainer.appendChild(fieldWrapper);
		});
		updateRequestButtonState();
	}

	function updateRequestButtonState() {
		const submitButton = document.querySelector(".request-qr");
		const attributeCheckboxes = attributesContainer.querySelectorAll('input[type="checkbox"]');
		const anySelected = Array.from(attributeCheckboxes).some(cb => cb.checked);
		submitButton.disabled = !anySelected;
	}

	typeDropdown.addEventListener("change", (e) => {
		renderFields(e.target.value);
	});

	document.querySelector("#select-all").addEventListener("click", () => {
		document.querySelectorAll("#attributes-container input[type=checkbox]:not(:disabled)").forEach(checkbox => {
			checkbox.checked = true;
		});
		updateRequestButtonState();
	});

	document.querySelector("#select-none").addEventListener("click", () => {
		document.querySelectorAll("#attributes-container input[type=checkbox]:not(:disabled)").forEach(checkbox => {
			checkbox.checked = false;
		});
		updateRequestButtonState();
	});

	form.addEventListener("submit", (e) => {
		e.preventDefault();
		const selectedType = typeDropdown.value;
		const credential = getCredentialByType(selectedType);
		const selectedClaims = Array.from(attributesContainer.querySelectorAll('input[type="checkbox"]:checked'))
			.map(cb => cb.value);

		const filteredClaims = (credential.claims || []).filter(claim =>
			selectedClaims.includes(claim.path.join("."))
		);

		const filteredCredential = { ...credential, claims: filteredClaims };
		const filteredDcqlQuery = { ...dcqlQuery, credentials: [filteredCredential] };
		dcqlQueryInput.value = JSON.stringify(filteredDcqlQuery);
		form.submit();
	});
	renderFields(typeDropdown.value);
});
