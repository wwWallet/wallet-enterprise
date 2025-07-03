var queryString = window.location.search;
var urlParams = new URLSearchParams(queryString);

if(urlParams.get('no_institution_was_selected')) {
	popupAlert('no-institution-was-selected');
}

document.getElementById('university-code').addEventListener('change', function (e) {
	const warningElement = document.getElementById('warning1');
	// if warning element is present, then disable it.
	if (warningElement != null) {
		warningElement.style.opacity = '0';
	}
});

document.forms.selectInstitutions.onsubmit = function(event) {

	const formData = new FormData(document.forms.selectInstitutions);
	const university = formData.get('university');

	if(university === null || university === "") {
		event.preventDefault();
		popupAlert('no-institution-was-selected');
		return;
	}

}
