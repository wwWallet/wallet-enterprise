
document.addEventListener("DOMContentLoaded", () => {
	const typeDropdown = document.getElementById("type");
	const attributesContainer = document.getElementById("attributes-container");
	function updateRequestButtonState() {
		const submitButton = document.querySelector(".request-qr");
		const attributeCheckboxes = attributesContainer.querySelectorAll('input[type="checkbox"]');
		const anySelected = Array.from(attributeCheckboxes).some(cb => cb.checked);
		submitButton.disabled = !anySelected;
	}
	const selectableFields = JSON.parse(document.querySelector('script[src="/js/configurable-presentation.js"]').dataset.fields);
	const presentationDefinitionId = document.querySelector('script[src="/js/configurable-presentation.js"]').dataset.presentationId;

	const descriptorIdInput = document.getElementById("descriptorId");

	const calculateDescriptorId = () => {
		const type = typeDropdown.value;
		if (type === "sd-jwt") {
			if (presentationDefinitionId === "CustomVerifiableId") {
				return "SdJwtPID";
			} else if (presentationDefinitionId === "POR") {
				return "POR";
			}
		} else if (type === "mdoc") {
			if (presentationDefinitionId === "CustomVerifiableId") {
				return "eu.europa.ec.eudi.pid.1";
			}
		}
		return "";
	};

	const updateDescriptorId = () => {
		descriptorIdInput.value = calculateDescriptorId();
	};
	typeDropdown.addEventListener("change", updateDescriptorId);
	updateDescriptorId();

	const updateAttributesContainer = (type) => {
		attributesContainer.innerHTML = "";

		const filteredFields = (type === "mdoc")
			? selectableFields.filter(([label, value]) => value.includes("eu.europa.ec.eudi"))
			: selectableFields.filter(([label, value]) => !value.includes("eu.europa.ec.eudi"));

		filteredFields.forEach(([label, value]) => {
			const fieldWrapper = document.createElement("div");
			fieldWrapper.classList.add("checkbox-wrapper");

			const input = document.createElement("input");
			input.type = "checkbox";
			input.name = "attributes[]";
			input.value = value;
			input.id = value;

			const labelElement = document.createElement("label");
			labelElement.htmlFor = value;
			labelElement.textContent = label;

			if (value === "$.vct" && type === "sd-jwt") {
				input.checked = true;
				input.disabled = true;
			}

			input.addEventListener("change", updateRequestButtonState);

			fieldWrapper.appendChild(input);
			fieldWrapper.appendChild(labelElement);
			attributesContainer.appendChild(fieldWrapper);
		});

		updateRequestButtonState();
	};

	typeDropdown.addEventListener("change", (event) => {
		updateAttributesContainer(event.target.value);
	});
	updateAttributesContainer(typeDropdown.value);
});
