
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
	const presentationDefinitionDescriptorId = document.querySelector('script[src="/js/configurable-presentation.js"]').dataset.presentationDescriptorId;
	const descriptorIdInput = document.getElementById("descriptorId");

	const calculateDescriptorId = () => {
		const type = typeDropdown.value;
		const sdJwtMap = {
			CustomVerifiableId: "SdJwtPID",
			POR: "POR",
			EuropeanHealthInsuranceCard: "EuropeanHealthInsuranceCard",
			PortableDocumentA1: "PortableDocumentA1",
			Bachelor: "Bachelor",
		};

		const mdocMap = {
			CustomVerifiableId: "eu.europa.ec.eudi.pid.1"
		};

		if (type === "sd-jwt" && sdJwtMap[presentationDefinitionId]) {
			return sdJwtMap[presentationDefinitionId];
		} else if (type === "mdoc" && mdocMap[presentationDefinitionId]) {
			return mdocMap[presentationDefinitionId];
		}
		return "";
	};

	const updateDescriptorId = () => {
		if (presentationDefinitionDescriptorId === 'undefined') {
			descriptorIdInput.value = calculateDescriptorId();
		} else {
			descriptorIdInput.value = presentationDefinitionDescriptorId;
		}
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

				const hiddenInput = document.createElement("input");
				hiddenInput.type = "hidden";
				hiddenInput.name = "attributes[]";
				hiddenInput.value = value;
				fieldWrapper.appendChild(hiddenInput);
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
