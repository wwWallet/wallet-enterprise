var numberOfSteps = 3;
var currentStep = 1;

document.getElementById('next-step').onclick = function (event) {
	if(currentStep < numberOfSteps) {
		if(createSubjectFormControl(currentStep) === 0) {
			hideStep(currentStep);
			currentStep++;
			showStep(currentStep);
		}
	}
}

document.getElementById('prev-step').onclick = function (event) {
	if(currentStep > 1) {
		hideStep(currentStep);
		currentStep--;
		showStep(currentStep);
	}
}

function hideStep(currentStep) {
	document.getElementById(`step${currentStep}`).className = "step";
	document.getElementById(`form-step${currentStep}`).className = "form-step";
	if(currentStep === numberOfSteps)
		document.getElementById(`submit`).className = "Btn Small hidden";
}

function showStep(currentStep) {
	document.getElementById(`step${currentStep}`).className = "active step";
	document.getElementById(`form-step${currentStep}`).className = "current form-step";
	switch(currentStep) {
		case 1:
			document.getElementById('prev-step').className = "prev hidden";
			break;
		case 2:
			document.getElementById('prev-step').className = "prev";
			document.getElementById('next-step').className = "next";
			break;
		case 3:
			document.getElementById('next-step').className = "next hidden";
			document.getElementById(`submit`).className = "Btn Small";
			break;
		default:
			break;
	}

}

function createSubjectFormControl(currentStep) {

	switch(currentStep) {
		case 1:	// presentation definition cannot be empty

			const schemas = document.querySelectorAll('.Schema');

			const selectedCredentialTypes = [];
			for (const schema of schemas) {
				if (schema.checked == true) {
					selectedCredentialTypes.push(schema);
				}
			}
			console.log("Selected types = ", selectedCredentialTypes)
			if (selectedCredentialTypes.length == 0) {
				showNoCredentialTypeWasSelectedError();
				return 1;
			}
			break;
		case 2:	// title cannot be empty
			if(document.getElementById('title').value.length === 0 ) {
				errorFeedback('title');
				return 1;
				}
			break;
		case 3:	// no form control on third step
			break;
		default:
			break;
	}
	return 0;
}

function showNoCredentialTypeWasSelectedError() {
	// remove hidden class
	document.getElementById('no-type-selected-err').classList.remove('Hidden')
}