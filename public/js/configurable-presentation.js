document.addEventListener("DOMContentLoaded", () => {
	const typeDropdown = document.getElementById("type");
	const attributesDropdown = document.getElementById("attribute");
	const selectedAttributesList = document.querySelector("#selectedAttributes");
	const form = document.querySelector(".presentation-form");
	// Parse selectableFields passed as a prop to the script tag
	const selectableFields = JSON.parse(document.querySelector('script[src="/js/configurable-presentation.js"]').dataset.fields);
	const presentationDefinitionId = document.querySelector('script[src="/js/configurable-presentation.js"]').dataset.presentationId;

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
			return ""; // Default or empty if no match
	};
	const descriptorIdInput = document.getElementById("descriptorId");
	const updateDescriptorId = () => {
			descriptorIdInput.value = calculateDescriptorId();
	};

	// Update descriptorId on type change
	typeDropdown.addEventListener("change", updateDescriptorId);

	// Initial population based on the default type
	updateDescriptorId();

	const addVCTAttribute = () => {
		// Check if "VCT (Credential Type)" is already added
		if (!selectedAttributesList.querySelector(`[data-attribute="$.vct"]`)) {
			const attributeContainer = document.createElement("li");
			attributeContainer.classList.add("attribute-item");
			attributeContainer.setAttribute("data-attribute", "$.vct");

			// Add "VCT" to the selected list
			attributeContainer.innerHTML = `
				<span class="attribute-name">Credential type</span>
				<input type="hidden" name="attributes[]" value="$.vct">
				<input type="hidden" name="optional[]" value="false" class="optional-field">
				<div class="container-switch">
					<span class="toggle-label">Required</span>
					<label class="switch">
						<input type="checkbox" checked disabled>
						<span class="slider round"></span>
					</label>
				</div>
				<button class="btn-delete" type="button" data-attribute="$.vct" disabled style="cursor: not-allowed;">
					<i class="fa fa-lock"></i> Locked
				</button>
			`;

			selectedAttributesList.appendChild(attributeContainer);

			// Hide placeholder if present
			const placeholder = selectedAttributesList.querySelector(".empty-placeholder");
			if (placeholder) placeholder.style.display = "none";
		}
	};

	const updateAttributesDropdown = (type) => {
		// Clear existing options in the attributes dropdown
		attributesDropdown.innerHTML = "";

		// Clear the selected attributes list
		Array.from(selectedAttributesList.querySelectorAll("li.attribute-item")).forEach((item) => item.remove());

		// Show placeholder if no attributes remain
		const placeholder = selectedAttributesList.querySelector(".empty-placeholder");
		if (placeholder) placeholder.style.display = "block";

		// Filter selectableFields based on the selected type
		const filteredFields =
			type === "mdoc"
				? selectableFields.filter(([label, value]) => value.includes("eu.europa.ec.eudi"))
				: selectableFields.filter(([label, value]) => !value.includes("eu.europa.ec.eudi"));

		// Populate the attributes dropdown with filtered fields
		filteredFields.forEach(([label, value]) => {
			if (value !== "$.vct") { // Exclude "VCT" from the dropdown
				const option = document.createElement("option");
				option.value = value;
				option.textContent = `${label}`;
				attributesDropdown.appendChild(option);
			}
		});

		// Automatically add "Credential type" if the type is "sd-jwt"
		if (type === "sd-jwt") {
			addVCTAttribute();
		}
	};

	// Initial population based on the default type
	updateAttributesDropdown(typeDropdown.value);

	// Update attributes dropdown and clear selected attributes when type changes
	typeDropdown.addEventListener("change", (event) => {
		updateAttributesDropdown(event.target.value);
	});

	attributesDropdown.addEventListener("change", () => {
		const selectedOptions = Array.from(attributesDropdown.selectedOptions);

		selectedOptions.forEach((option) => {
			const attributeValue = option.value;
			const attributeText = option.textContent;

			// Check if attribute is already added
			if (!selectedAttributesList.querySelector(`[data-attribute="${attributeValue}"]`)) {
				const attributeContainer = document.createElement("li");
				attributeContainer.classList.add("attribute-item");
				attributeContainer.setAttribute("data-attribute", attributeValue);

				attributeContainer.innerHTML = `
					<span class="attribute-name">${attributeText}</span>
					<input type="hidden" name="attributes[]" value="${attributeValue}">
					<input type="hidden" name="optional[]" value="false" class="optional-field">
					<div class="container-switch">
						<span class="toggle-label">Required</span>
						<label class="switch">
							<input type="checkbox" checked disabled>
							<span class="slider round"></span>
						</label>
					</div>
					<button class="btn-delete" type="button" data-attribute="${attributeValue}" onclick="removeAttributeField(this)">
						<i class="fa fa-trash"></i> Delete
					</button>
				`;

				selectedAttributesList.appendChild(attributeContainer);
			}

			// Remove from dropdown
			option.remove();
		});

		// Hide placeholder if attributes are added
		const placeholder = selectedAttributesList.querySelector(".empty-placeholder");
		if (placeholder) placeholder.style.display = "none";
	});
});

// Remove attribute field and add it back to the dropdown
function removeAttributeField(button) {
	const attributeContainer = button.parentElement;
	const attributeDropdown = document.querySelector("#attribute");

	const attributeValue = button.getAttribute("data-attribute");
	const attributeText = attributeContainer.querySelector(".attribute-name").textContent;

	// Prevent removal of "VCT (Credential type)"
	if (attributeValue === "$.vct") return;

	// Re-add the option to the dropdown with the correct value and text
	const option = document.createElement("option");
	option.value = attributeValue;
	option.textContent = attributeText;
	attributeDropdown.appendChild(option);

	attributeContainer.remove();

	// Show placeholder if no attributes remain
	const selectedAttributesList = document.querySelector("#selectedAttributes");
	if (!selectedAttributesList.querySelector(".attribute-item")) {
		const placeholder = selectedAttributesList.querySelector(".empty-placeholder");
		if (placeholder) placeholder.style.display = "block";
	}
}
