const layout = document.querySelector('.layout');

const cards = document.querySelectorAll('.credential-card');
const toggleButtons = document.querySelectorAll('.toggle-details');

const form = document.querySelector('#DiplomaSelection');
const submitMultiButton = document.querySelector('.GetMultiBtn');
const barBtnContainer = document.querySelector('.BarBtnContainer');

function deselectAllCards() {
	deselectAllInputs();
	document.querySelectorAll('.credential').forEach(credential => {
		credential.classList.remove('selected');
	});
}

function hideAllDropdowns() {
	deselectAllInputs();
	cards.forEach(card => hideDropdown(card));
}

function hideDropdown(card) {

	const details = card.querySelector('.details');
	const arrowDown = card.querySelector('.arrowDown');
	card.classList.remove('expanded');

	details.style.maxHeight = '0';
	arrowDown.style.display = 'none';
}

function showDropdown(card) {

	hideAllDropdowns();

	const details = card.querySelector('.details');
	const arrowDown = card.querySelector('.arrowDown');

	details.style.maxHeight = `${details.scrollHeight}px`;
	arrowDown.style.display = 'block';

	card.classList.add('expanded');
}

toggleButtons.forEach(toggleButton => {
	toggleButton.addEventListener('click', (e) => {

		const thisId = e.target.id;
		const card = document.getElementById(thisId).parentElement;

		if(layout.classList.contains('multi')) {
			e.target.classList.toggle('selected');
			toggleInput(thisId);
		}
		else {
			if (card.classList.contains('expanded')) {
				hideDropdown(card);
				deselectInput(thisId);
			} else {
				showDropdown(card);
				selectInput(thisId);
			}
		}
	});
});


const selectMultiButton = document.querySelector('.SelectMultiBtn');
const consentDescription = document.querySelector('.consent-description');
const isSelectedCircle = document.querySelector('.is-selected');
const barBtn = document.querySelector('#BarBtn');

selectMultiButton.addEventListener('click', () => {
	
	selectMultiButton.classList.toggle('toggled');
	barBtnContainer.classList.toggle('multi');
	layout.classList.toggle('multi');

	if (selectMultiButton.classList.contains('toggled')) {
		selectMultiButton.innerHTML = "Cancel";
		consentDescription.innerHTML = "Select your credentials by clicking on them and authorize the sharing of all selected credentials with the client";
		hideAllDropdowns();
	}
	else {
		selectMultiButton.innerHTML = "Select";
		consentDescription.innerHTML = "Inspect your credentials by clicking on them and authorize the sharing of one of them with the client";
		deselectAllCards();
	}
});

function deselectInput(value) {
	const inputs = document.querySelectorAll('input');

	inputs.forEach(input => {
		if(input.value === value)
			input.disabled = true;
	});

	if(!isOneInputEnabled())
		disableSubmitButtons();

}

function selectInput(value) {
	const inputs = document.querySelectorAll('input');

	inputs.forEach(input => {
		if(input.value === value)
			input.disabled = false;
	});

	enableSubmitButtons();
}

function toggleInput(value) {
	const inputs = document.querySelectorAll('input');

	inputs.forEach(input => {
		if(input.value === value) {
			input.disabled = !input.disabled;
		}

		if(isOneInputEnabled()) {
			enableSubmitButtons();
		}
		else {
			disableSubmitButtons();
		}
	});
}

function deselectAllInputs() {
	const inputs = document.querySelectorAll('input:not([type=checkbox])');
	inputs.forEach(input => input.disabled = true);
	disableSubmitButtons();
}

submitMultiButton.addEventListener('click', (e) => {
	e.preventDefault();

	let enabledInputFlag = isOneInputEnabled();
	if(enabledInputFlag)
		form.submit();
	else
		noCredentialsError();
});

function noCredentialsError(timeout=3000) {

	const errorText = document.querySelector('#NoCredentialSelectedError');

	errorText.classList.remove('Hidden');

	setTimeout(() => {
		errorText.classList.add('Hidden');
	}, timeout);
}

function isOneInputEnabled() {
	let enabledInputFlag = false;
	const inputs = document.querySelectorAll('input');
	for (const input of inputs) {
		if(input.disabled === false) {
			enabledInputFlag = true;
			break;
		}
	};

	return enabledInputFlag;
}

barBtn.addEventListener('click', (e) => {
	let enabledInputFlag = isOneInputEnabled();
	if(enabledInputFlag)
		form.submit();
	else
		noCredentialsError();
})

function disableSubmitButtons() {
	submitMultiButton.disabled = true;
	barBtn.disabled = true;
}

function enableSubmitButtons() {
	submitMultiButton.disabled = false;
	barBtn.disabled = false;
}